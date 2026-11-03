package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"zainvpn/internal/proto"
	"zainvpn/internal/server"
)

const waitTimeout = 10 * time.Second

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// fakeHost stands in for the virtual adapter.
type fakeHost struct {
	mu    sync.Mutex
	addrs []netip.Prefix
	pkts  chan []byte
}

func (h *fakeHost) WritePacket(pkt []byte) error {
	select {
	case h.pkts <- bytes.Clone(pkt): // the engine reuses its buffer
	default: // never block the engine; an overflow shows up as a missing packet
	}
	return nil
}

func (h *fakeHost) SetAddress(p netip.Prefix) error {
	h.mu.Lock()
	h.addrs = append(h.addrs, p)
	h.mu.Unlock()
	return nil
}

func (h *fakeHost) addresses() []netip.Prefix {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.addrs)
}

func (h *fakeHost) expect(t *testing.T, want []byte, desc string) {
	t.Helper()
	select {
	case got := <-h.pkts:
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: got %s, want %s", desc, describe(got), describe(want))
		}
	case <-time.After(waitTimeout / 2):
		t.Fatalf("%s: %s not delivered", desc, describe(want))
	}
}

// expectQuiet checks that none of the hosts receives anything for a while.
func expectQuiet(t *testing.T, d time.Duration, engines ...*testEngine) {
	t.Helper()
	time.Sleep(d)
	for _, e := range engines {
		select {
		case got := <-e.host.pkts:
			t.Errorf("%s: unexpected packet %s", e.cfg.Name, describe(got))
		default:
		}
	}
}

type testEnv struct {
	t    *testing.T
	logs *logBuf
	srv  *server.Server
	addr string // coordinator, TCP and UDP
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	logs := &logBuf{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("logs:\n%s", logs)
		}
	})
	srv, err := server.New("", log.New(logs, "server: ", log.Lmicroseconds))
	if err != nil {
		t.Fatal(err)
	}
	ln, udp := listenPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.Serve(ln, udp)
	}()
	t.Cleanup(func() {
		ln.Close()
		udp.Close()
		<-done
	})
	return &testEnv{t: t, logs: logs, srv: srv, addr: ln.Addr().String()}
}

func listenPair(t *testing.T) (net.Listener, *net.UDPConn) {
	t.Helper()
	for range 20 {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		udp, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(ln.Addr().(*net.TCPAddr).AddrPort()))
		if err == nil {
			return ln, udp
		}
		ln.Close()
	}
	t.Fatal("no free TCP+UDP port pair")
	return nil, nil
}

type testEngine struct {
	*Engine
	host *fakeHost
	stop func() // cancels Run and waits for it to return
}

func (env *testEnv) engine(name, network, password string, noDirect bool) *testEngine {
	return env.engineAt(env.addr, name, network, password, noDirect)
}

func (env *testEnv) engineAt(server, name, network, password string, noDirect bool) *testEngine {
	t := env.t
	host := &fakeHost{pkts: make(chan []byte, 256)}
	cfg := Config{Server: server, Network: network, Password: password, Name: name, DeviceID: "dev-" + name}
	e := New(cfg, host, log.New(env.logs, name+": ", log.Lmicroseconds))
	e.bind = netip.MustParseAddrPort("127.0.0.1:0")
	e.noDirect = noDirect

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("%s: Run: %v", name, err)
				}
			case <-time.After(waitTimeout):
				t.Errorf("%s: Run didn't return after cancel", name)
			}
		})
	}
	t.Cleanup(stop)
	return &testEngine{Engine: e, host: host, stop: stop}
}

// addr is the engine's virtual IP (invalid until it is first online).
func (e *testEngine) addr() netip.Addr {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ip
}

// udpAddr is the engine's UDP socket; only valid once Run has started.
func (e *testEngine) udpAddr() netip.AddrPort {
	return e.udp.LocalAddr().(*net.UDPAddr).AddrPort()
}

func waitFor(t *testing.T, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		err := cond()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func findPeer(st Status, ip netip.Addr) (PeerStatus, bool) {
	for _, p := range st.Peers {
		if p.IP == ip.String() {
			return p, true
		}
	}
	return PeerStatus{}, false
}

// waitReady waits until every engine is online and registered with the relay,
// and knows every other engine's public endpoint (so the coordinator can relay
// to it).
func waitReady(t *testing.T, engines ...*testEngine) {
	t.Helper()
	waitFor(t, func() error {
		for _, e := range engines {
			st := e.Status()
			if st.State != StateOnline || !st.Relay {
				return fmt.Errorf("%s: state %q, relay %v, message %q", st.Name, st.State, st.Relay, st.Message)
			}
			for _, o := range engines {
				if o == e {
					continue
				}
				ip := o.addr()
				if ps, ok := findPeer(st, ip); !ok || !ps.Online {
					return fmt.Errorf("%s doesn't see %s (%s) online: %+v", st.Name, o.cfg.Name, ip, st.Peers)
				}
				e.mu.Lock()
				n := len(e.peers[ip].candidates)
				e.mu.Unlock()
				if n == 0 {
					return fmt.Errorf("%s has no endpoint for %s yet", st.Name, o.cfg.Name)
				}
			}
		}
		return nil
	})
}

// waitPath waits until e reaches peer over the given path ("direct" or "relay").
func waitPath(t *testing.T, e, peer *testEngine, path string) PeerStatus {
	t.Helper()
	var ps PeerStatus
	waitFor(t, func() error {
		var ok bool
		ps, ok = findPeer(e.Status(), peer.addr())
		if !ok || ps.Path != path {
			return fmt.Errorf("%s -> %s: %+v, want path %s", e.cfg.Name, peer.cfg.Name, ps, path)
		}
		if path == "relay" && ps.RTTms <= 0 {
			return fmt.Errorf("%s -> %s: no relay RTT yet", e.cfg.Name, peer.cfg.Name)
		}
		return nil
	})
	return ps
}

// ipv4UDP builds an IPv4/UDP packet as the OS would hand it to the adapter.
func ipv4UDP(src, dst netip.Addr, payload string) []byte {
	pkt := make([]byte, 28+len(payload))
	pkt[0] = 0x45 // version 4, 20-byte header
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:], checksum(pkt[:20]))
	binary.BigEndian.PutUint16(pkt[20:], 50000)
	binary.BigEndian.PutUint16(pkt[22:], 50001)
	binary.BigEndian.PutUint16(pkt[24:], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	return pkt
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

func describe(pkt []byte) string {
	if len(pkt) < 28 {
		return fmt.Sprintf("% x", pkt)
	}
	payload := string(pkt[28:])
	if len(payload) > 40 {
		payload = payload[:40] + "..."
	}
	return fmt.Sprintf("[%s -> %s, %d bytes, %q]",
		netip.AddrFrom4([4]byte(pkt[12:16])), netip.AddrFrom4([4]byte(pkt[16:20])), len(pkt), payload)
}

func TestStatusBeforeRun(t *testing.T) {
	cfg := Config{Server: "example.com", Network: "LAN", Password: "pw", Name: "zain", DeviceID: "d"}
	e := New(cfg, &fakeHost{pkts: make(chan []byte, 1)}, log.New(&logBuf{}, "", 0))
	st := e.Status()
	if st.State != StateStarting || st.IP != "" || st.Relay || st.Peers == nil || len(st.Peers) != 0 ||
		st.Name != "zain" || st.Network != "LAN" || st.Server != "example.com" {
		t.Errorf("status before Run = %+v", st)
	}
	e.HandleOutbound(ipv4UDP(netip.MustParseAddr("10.77.0.1"), proto.Broadcast, "early")) // must not panic
	e.HandleOutbound(nil)
}

func TestEnginesComeOnline(t *testing.T) {
	env := newEnv(t)
	a := env.engine("alice", "LAN Party", "hunter2", false)
	b := env.engine("bob", " lan party", "hunter2", false)
	waitReady(t, a, b)

	ipA, ipB := a.addr(), b.addr()
	if ipA == ipB || !proto.Subnet.Contains(ipA) || !proto.Subnet.Contains(ipB) ||
		ipA == proto.Subnet.Addr() || ipB == proto.Broadcast {
		t.Fatalf("addresses %s and %s", ipA, ipB)
	}
	for _, e := range []*testEngine{a, b} {
		want := []netip.Prefix{netip.PrefixFrom(e.addr(), 24)}
		if got := e.host.addresses(); !slices.Equal(got, want) {
			t.Errorf("%s: SetAddress calls %v, want %v", e.cfg.Name, got, want)
		}
	}

	st := a.Status()
	if st.IP != ipA.String() || st.Name != "alice" || st.Network != "LAN Party" || st.Server != env.addr || st.Message != "" {
		t.Errorf("alice's status = %+v", st)
	}
	if len(st.Peers) != 1 || st.Peers[0].Name != "bob" || st.Peers[0].IP != ipB.String() || !st.Peers[0].Online {
		t.Errorf("alice's peers = %+v", st.Peers)
	}
	snap := env.srv.Snapshot()
	if len(snap.Networks) != 1 || snap.Networks[0].Name != "lan party" || snap.Networks[0].Online != 2 {
		t.Errorf("coordinator networks = %+v", snap.Networks)
	}
}

func TestDirectPath(t *testing.T) {
	env := newEnv(t)
	a := env.engine("alice", "lan", "hunter2", false)
	b := env.engine("bob", "lan", "hunter2", false)
	waitReady(t, a, b)
	ab, ba := waitPath(t, a, b, "direct"), waitPath(t, b, a, "direct")
	if ab.Endpoint != b.udpAddr().String() || ba.Endpoint != a.udpAddr().String() || ab.RTTms < 0 || ba.RTTms < 0 {
		t.Errorf("direct paths: alice->bob %+v (bob at %s), bob->alice %+v (alice at %s)", ab, b.udpAddr(), ba, a.udpAddr())
	}
	ipA, ipB := a.addr(), b.addr()

	relayed := env.srv.Snapshot().RelayPackets
	const n = 5
	for i := range n {
		p := ipv4UDP(ipA, ipB, fmt.Sprintf("hello bob %d", i))
		a.HandleOutbound(p)
		b.host.expect(t, p, "alice -> bob")
		p = ipv4UDP(ipB, ipA, fmt.Sprintf("hello alice %d", i))
		b.HandleOutbound(p)
		a.host.expect(t, p, "bob -> alice")
	}
	// A probe might still have been in flight through the relay, but not the data.
	if d := env.srv.Snapshot().RelayPackets - relayed; d >= 2*n {
		t.Errorf("%d packets went through the relay on a direct path", d)
	}

	// A full-MTU packet makes it, and the engine doesn't hold on to the caller's buffer.
	big := ipv4UDP(ipA, ipB, strings.Repeat("x", proto.MTU-28))
	want := bytes.Clone(big)
	a.HandleOutbound(big)
	clear(big)
	b.host.expect(t, want, "full-size packet")

	// Unknown destinations go nowhere.
	a.HandleOutbound(ipv4UDP(ipA, netip.MustParseAddr("10.77.0.200"), "nobody"))
	a.HandleOutbound(ipv4UDP(ipA, ipA, "myself"))
	sentinel := ipv4UDP(ipA, ipB, "sentinel")
	a.HandleOutbound(sentinel)
	b.host.expect(t, sentinel, "sentinel")
	expectQuiet(t, 100*time.Millisecond, a, b)
}

func TestRelayOnly(t *testing.T) {
	env := newEnv(t)
	a := env.engine("alice", "lan", "hunter2", true)
	b := env.engine("bob", "lan", "hunter2", true)
	waitReady(t, a, b)
	waitPath(t, a, b, "relay")
	waitPath(t, b, a, "relay")
	ipA, ipB := a.addr(), b.addr()

	before := env.srv.Snapshot()
	var bytesSent uint64
	const n = 5
	for i := range n {
		p := ipv4UDP(ipA, ipB, fmt.Sprintf("relayed to bob %d", i))
		a.HandleOutbound(p)
		b.host.expect(t, p, "alice -> bob")
		q := ipv4UDP(ipB, ipA, fmt.Sprintf("relayed to alice %d", i))
		b.HandleOutbound(q)
		a.host.expect(t, q, "bob -> alice")
		bytesSent += uint64(len(p) + len(q) + 2*proto.Overhead)
	}
	after := env.srv.Snapshot()
	if after.RelayPackets-before.RelayPackets < 2*n || after.RelayBytes-before.RelayBytes < bytesSent {
		t.Errorf("relay counters went from %d/%d to %d/%d, want at least +%d packets / +%d bytes",
			before.RelayPackets, before.RelayBytes, after.RelayPackets, after.RelayBytes, 2*n, bytesSent)
	}
	for _, d := range after.Networks[0].Devices {
		if d.RelayBytes == 0 {
			t.Errorf("device %s has no relay bytes", d.Name)
		}
	}
	for _, pair := range [][2]*testEngine{{a, b}, {b, a}} {
		if ps, _ := findPeer(pair[0].Status(), pair[1].addr()); ps.Path != "relay" || ps.Endpoint != "" {
			t.Errorf("%s -> %s: %+v, want relay", pair[0].cfg.Name, pair[1].cfg.Name, ps)
		}
	}
}

func TestBroadcastAndMulticast(t *testing.T) {
	for _, mode := range []string{"direct", "relay"} {
		t.Run(mode, func(t *testing.T) {
			env := newEnv(t)
			noDirect := mode == "relay"
			a := env.engine("alice", "lan", "hunter2", noDirect)
			b := env.engine("bob", "lan", "hunter2", noDirect)
			c := env.engine("carol", "lan", "hunter2", noDirect)
			all := []*testEngine{a, b, c}
			waitReady(t, all...)
			for _, e := range all {
				for _, o := range all {
					if e != o {
						waitPath(t, e, o, mode)
					}
				}
			}
			before := env.srv.Snapshot().RelayPackets

			ipA := a.addr()
			for _, dst := range []string{"255.255.255.255", "10.77.0.255", "224.0.0.251", "239.255.255.250"} {
				p := ipv4UDP(ipA, netip.MustParseAddr(dst), "discover "+dst)
				a.HandleOutbound(p)
				b.host.expect(t, p, "bob, from alice to "+dst)
				c.host.expect(t, p, "carol, from alice to "+dst)
			}
			p := ipv4UDP(b.addr(), proto.LimitedBroadcast, "bob's game is open")
			b.HandleOutbound(p)
			a.host.expect(t, p, "alice, bob's broadcast")
			c.host.expect(t, p, "carol, bob's broadcast")

			// Unicast still only reaches its target, and nobody hears its own broadcasts.
			p = ipv4UDP(ipA, c.addr(), "just carol")
			a.HandleOutbound(p)
			c.host.expect(t, p, "carol, unicast")
			expectQuiet(t, 200*time.Millisecond, all...)

			if relayed := env.srv.Snapshot().RelayPackets - before; noDirect && relayed < 11 {
				t.Errorf("only %d packets went through the relay, want at least 11", relayed)
			}
		})
	}
}

func TestSpoofedPacketsDropped(t *testing.T) {
	env := newEnv(t)
	a := env.engine("alice", "lan", "hunter2", false)
	b := env.engine("bob", "lan", "hunter2", false)
	waitReady(t, a, b)
	waitPath(t, a, b, "direct") // so hand-made and engine packets take the same path
	ipA, ipB := a.addr(), b.addr()
	other := netip.MustParseAddr("10.77.0.99")
	inject := func(k *proto.Keys, dst, src netip.Addr, inner []byte) {
		if _, err := a.udp.WriteToUDPAddrPort(k.Seal(proto.TypeData, dst, src, inner), b.udpAddr()); err != nil {
			t.Fatal(err)
		}
	}

	// Control: a well-formed hand-sealed packet is delivered.
	ok := ipv4UDP(ipA, ipB, "hand-sealed")
	inject(a.keys, ipB, ipA, ok)
	b.host.expect(t, ok, "hand-sealed control packet")

	// The sender refuses packets that aren't from its own address.
	a.HandleOutbound(ipv4UDP(other, ipB, "spoofed by alice's OS"))
	a.HandleOutbound(ipv4UDP(ipB, ipB, "pretending to be bob"))

	// The receiver drops packets whose inner source isn't the sending peer,
	inject(a.keys, ipB, ipA, ipv4UDP(other, ipB, "inner src spoofed"))
	// that aren't addressed to it,
	inject(a.keys, ipB, ipA, ipv4UDP(ipA, other, "inner dst elsewhere"))
	inject(a.keys, ipA, ipA, ipv4UDP(ipA, ipB, "outer dst elsewhere"))
	// that come from an unknown peer,
	inject(a.keys, ipB, other, ipv4UDP(other, ipB, "unknown peer"))
	// that aren't valid IPv4,
	v6 := ipv4UDP(ipA, ipB, "version 6")
	v6[0] = 0x65
	inject(a.keys, ipB, ipA, v6)
	ihl := ipv4UDP(ipA, ipB, "x")
	ihl[0] = 0x4f // 60-byte header in a 29-byte packet
	inject(a.keys, ipB, ipA, ihl)
	inject(a.keys, ipB, ipA, ok[:19])
	// or that weren't sealed with this network's key.
	wrong, err := proto.DeriveKeys("lan", "not the password")
	if err != nil {
		t.Fatal(err)
	}
	inject(wrong, ipB, ipA, ipv4UDP(ipA, ipB, "wrong key"))
	a.udp.WriteToUDPAddrPort(append([]byte{proto.TypeData}, make([]byte, proto.Overhead)...), b.udpAddr())

	sentinel := ipv4UDP(ipA, ipB, "sentinel")
	a.HandleOutbound(sentinel)
	b.host.expect(t, sentinel, "sentinel (was a bad packet delivered first?)")
	expectQuiet(t, 100*time.Millisecond, a, b)
}

func TestWrongPassword(t *testing.T) {
	env := newEnv(t)
	a := env.engine("alice", "lan", "hunter2", false)
	waitFor(t, func() error {
		if st := a.Status(); st.State != StateOnline {
			return fmt.Errorf("alice: %+v", st)
		}
		return nil
	})
	m := env.engine("mallory", "LAN", "letmein", false)
	waitFor(t, func() error {
		if st := m.Status(); st.State != StateError {
			return fmt.Errorf("mallory: %+v, want state %q", st, StateError)
		}
		return nil
	})
	st := m.Status()
	if !strings.Contains(strings.ToLower(st.Message), "password") || st.IP != "" || len(st.Peers) != 0 {
		t.Errorf("mallory's status = %+v, want an error about the password", st)
	}
	if addrs := m.host.addresses(); len(addrs) != 0 {
		t.Errorf("mallory's adapter was configured: %v", addrs)
	}
	if st := a.Status(); len(st.Peers) != 0 {
		t.Errorf("alice sees %+v", st.Peers)
	}
	if nw := env.srv.Snapshot().Networks[0]; len(nw.Devices) != 1 {
		t.Errorf("coordinator devices = %+v", nw.Devices)
	}
}

func TestCoordinatorUnreachable(t *testing.T) {
	env := newEnv(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	ln.Close()
	e := env.engineAt(closed, "alice", "lan", "hunter2", false)
	waitFor(t, func() error {
		if st := e.Status(); st.State != StateConnecting || st.Message == "" {
			return fmt.Errorf("status %+v, want connecting with an error message", st)
		}
		return nil
	})
}

func TestPeerGoesOffline(t *testing.T) {
	env := newEnv(t)
	a := env.engine("alice", "lan", "hunter2", false)
	b := env.engine("bob", "lan", "hunter2", false)
	waitReady(t, a, b)
	waitPath(t, a, b, "direct")
	ipB := b.addr()

	b.stop()
	waitFor(t, func() error {
		ps, ok := findPeer(a.Status(), ipB)
		if !ok || ps.Online || ps.Path != "offline" || ps.RTTms != -1 || ps.Endpoint != "" {
			return fmt.Errorf("alice sees bob as %+v (present %v), want offline", ps, ok)
		}
		return nil
	})
	if nw := env.srv.Snapshot().Networks[0]; nw.Online != 1 || len(nw.Devices) != 2 {
		t.Errorf("coordinator network = %+v", nw)
	}
	a.HandleOutbound(ipv4UDP(a.addr(), ipB, "anyone there?")) // must not panic
	a.HandleOutbound(ipv4UDP(a.addr(), proto.Broadcast, "anyone there?"))
	if st := a.Status(); st.State != StateOnline {
		t.Errorf("alice = %+v", st)
	}
}

func TestReconnect(t *testing.T) {
	env := newEnv(t)
	a := env.engine("alice", "lan", "hunter2", false)
	b := env.engine("bob", "lan", "hunter2", false)
	waitReady(t, a, b)
	ipB := b.addr()

	// connectedAfter waits until the coordinator has the devices online,
	// registered, on connections made after t0.
	connectedAfter := func(t0 time.Time, ids ...string) {
		t.Helper()
		waitFor(t, func() error {
			snap := env.srv.Snapshot()
			if len(snap.Networks) != 1 {
				return fmt.Errorf("networks %+v", snap.Networks)
			}
			for _, id := range ids {
				i := slices.IndexFunc(snap.Networks[0].Devices, func(d server.DeviceInfo) bool { return d.ID == id })
				if i < 0 {
					return fmt.Errorf("%s not in %+v", id, snap.Networks[0].Devices)
				}
				if d := snap.Networks[0].Devices[i]; !d.Online || d.Public == "" || !d.Connected.After(t0) {
					return fmt.Errorf("%s: %+v", id, d)
				}
			}
			return nil
		})
	}
	exchange := func() {
		t.Helper()
		ipA, ipB := a.addr(), b.addr()
		p := ipv4UDP(ipA, ipB, "still there, bob?")
		a.HandleOutbound(p)
		b.host.expect(t, p, "alice -> bob")
		p = ipv4UDP(ipB, ipA, "yes")
		b.HandleOutbound(p)
		a.host.expect(t, p, "bob -> alice")
	}

	// Kicked: bob reconnects by himself and gets his (freed) address back.
	t0 := time.Now().UTC()
	if err := env.srv.RemoveDevice("lan", "dev-bob"); err != nil {
		t.Fatal(err)
	}
	connectedAfter(t0, "dev-bob")
	waitReady(t, a, b)
	if b.addr() != ipB || len(b.host.addresses()) != 1 {
		t.Errorf("bob came back as %s (was %s), SetAddress calls %v", b.addr(), ipB, b.host.addresses())
	}
	exchange()

	// Network deleted: both reconnect and recreate it, maybe with swapped addresses.
	t0 = time.Now().UTC()
	if err := env.srv.DeleteNetwork("lan"); err != nil {
		t.Fatal(err)
	}
	connectedAfter(t0, "dev-alice", "dev-bob")
	waitReady(t, a, b)
	if a.addr() == b.addr() {
		t.Fatalf("both got %s", a.addr())
	}
	for _, e := range []*testEngine{a, b} {
		addrs := e.host.addresses()
		if addrs[len(addrs)-1] != netip.PrefixFrom(e.addr(), 24) {
			t.Errorf("%s: SetAddress calls %v, current address %s", e.cfg.Name, addrs, e.addr())
		}
		if st := e.Status(); len(st.Peers) != 1 {
			t.Errorf("%s: peers %+v", e.cfg.Name, st.Peers)
		}
	}
	exchange()
}
