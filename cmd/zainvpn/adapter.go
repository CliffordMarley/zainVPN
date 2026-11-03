//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"zainvpn/internal/client"
	"zainvpn/internal/proto"
)

// adapterGUID is fixed so Windows recognizes the adapter as the same network
// (and keeps its network profile) every time it is recreated.
var adapterGUID = windows.GUID{
	Data1: 0x7a61696e, Data2: 0x5650, Data3: 0x4e4c,
	Data4: [8]byte{0x8f, 0x3a, 0x51, 0xc2, 0x6d, 0x0b, 0x94, 0x17},
}

// openAdapter creates the Wintun adapter, retrying for a while because the
// driver can be busy right after boot.
func openAdapter(ctx context.Context, logger *log.Logger) (*tun.NativeTun, error) {
	tun.WintunTunnelType = adapterName
	delays := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second}
	for i := 0; ; i++ {
		dev, err := tun.CreateTUNWithRequestedGUID(adapterName, &adapterGUID, proto.MTU)
		if err == nil {
			return dev.(*tun.NativeTun), nil
		}
		if i == len(delays) {
			return nil, fmt.Errorf("create network adapter: %w", err)
		}
		logger.Printf("create network adapter: %v (retrying in %s)", err, delays[i])
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delays[i]):
		}
	}
}

// adapterHost implements client.Host on the Wintun adapter.
type adapterHost struct {
	dev     *tun.NativeTun
	luid    winipcfg.LUID
	log     *log.Logger
	profile chan struct{} // asks profileLoop to mark the network Private

	wmu  sync.Mutex // wireguard-go's tun Write isn't safe for concurrent use
	wbuf [1][]byte
}

func newAdapterHost(ctx context.Context, dev *tun.NativeTun, logger *log.Logger) *adapterHost {
	h := &adapterHost{dev: dev, luid: winipcfg.LUID(dev.LUID()), log: logger, profile: make(chan struct{}, 1)}
	if err := h.configure(); err != nil {
		logger.Printf("configure adapter: %v", err)
	}
	go h.profileLoop(ctx)
	return h
}

func (h *adapterHost) WritePacket(pkt []byte) error {
	h.wmu.Lock()
	defer h.wmu.Unlock()
	h.wbuf[0] = pkt
	_, err := h.dev.Write(h.wbuf[:], 0)
	h.wbuf[0] = nil
	return err
}

func (h *adapterHost) SetAddress(p netip.Prefix) error {
	err := h.luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{p})
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		h.removeStaleAddress(p.Addr())
		err = h.luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{p})
	}
	if err != nil {
		return err
	}
	h.luid.FlushIPAddresses(windows.AF_INET6) // IPv4-only network
	if err := h.configure(); err != nil {
		h.log.Printf("configure adapter: %v", err)
	}
	h.log.Printf("adapter address %s", p)
	select {
	case h.profile <- struct{}{}:
	default:
	}
	return nil
}

// configure sets the interface metric to 1, so Windows sends 255.255.255.255
// broadcasts (LAN game discovery) out of this adapter, and the MTU. The
// interface row may not exist yet right after the adapter is created.
func (h *adapterHost) configure() error {
	var err error
	for range 20 {
		var row *winipcfg.MibIPInterfaceRow
		if row, err = h.luid.IPInterface(windows.AF_INET); err == nil {
			row.UseAutomaticMetric = false
			row.Metric = 1
			row.NLMTU = proto.MTU
			row.DadTransmits = 0 // address usable immediately
			row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
			if err = row.Set(); err == nil {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return err
}

// removeStaleAddress frees addr from disconnected interfaces (e.g. an
// adapter left behind by a crash), which would make assigning it fail.
func (h *adapterHost) removeStaleAddress(addr netip.Addr) {
	ifaces, err := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if iface.LUID == h.luid || iface.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for a := iface.FirstUnicastAddress; a != nil; a = a.Next {
			if ip, ok := netip.AddrFromSlice(a.Address.IP()); ok && ip.Unmap() == addr {
				h.log.Printf("removing stale address %s from %q", addr, iface.FriendlyName())
				iface.LUID.DeleteIPAddress(netip.PrefixFrom(addr, int(a.OnLinkPrefixLength)))
			}
		}
	}
}

// profileLoop marks the zainVPN network Private after each address change,
// so Windows Firewall and games treat friends like a home LAN. Windows only
// identifies the network a few seconds after the address appears, hence the
// retries. Failures are only logged.
func (h *adapterHost) profileLoop(ctx context.Context) {
	ps := systemTool(`WindowsPowerShell\v1.0\powershell.exe`)
	args := fmt.Sprintf(`-NoProfile -NonInteractive -Command "Set-NetConnectionProfile -InterfaceAlias '%s' -NetworkCategory Private -ErrorAction Stop"`, adapterName)
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.profile:
		}
		deadline := time.Now().Add(60 * time.Second)
		for {
			out, err := runHidden(ctx, ps, args)
			if err == nil {
				h.log.Printf("network profile set to Private")
				break
			}
			if ctx.Err() != nil {
				return
			}
			if time.Now().After(deadline) {
				h.log.Printf("set network profile to Private: %v: %s", err, out)
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// readTUN passes every packet the OS sends to the adapter to the current
// engine. It is the only reader, as the tun device requires. It returns nil
// once the device is closed.
func readTUN(dev tun.Device, eng *atomic.Pointer[client.Engine]) error {
	bufs := [][]byte{make([]byte, 65535)}
	sizes := []int{0}
	for {
		n, err := dev.Read(bufs, sizes, 0)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return nil
			}
			return err
		}
		if n == 1 {
			if e := eng.Load(); e != nil {
				e.HandleOutbound(bufs[0][:sizes[0]])
			}
		}
	}
}
