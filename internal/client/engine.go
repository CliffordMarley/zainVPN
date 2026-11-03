// Package client is the platform-independent core of the zainVPN client. It
// talks to the coordinator, keeps a path (direct or relayed) to every peer,
// and moves IPv4 packets between the virtual adapter and the network.
package client

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"zainvpn/internal/proto"
)

const (
	dialTimeout    = 10 * time.Second
	readTimeout    = 60 * time.Second
	ctrlPing       = 20 * time.Second
	registerEvery  = 10 * time.Second
	registerRetry  = time.Second
	directTimeout  = 12 * time.Second // no pong for this long: fall back to relay
	punchFast      = 2 * time.Second  // probe interval while looking for a direct path
	punchSlow      = 8 * time.Second  // ...once fast punching has failed for a while
	punchFastFor   = 30 * time.Second
	keepalive      = 4 * time.Second // probe interval on a working direct path
	maxBackoff     = 15 * time.Second
	refusedBackoff = 30 * time.Second
)

// Config is what a user sets up once.
type Config struct {
	Server   string `json:"server"` // host or host:port of the coordinator
	Invite   string `json:"invite"` // invite code of the network to be in; "" for none
	Name     string `json:"name"`
	DeviceID string `json:"deviceId"`
}

// Host is the platform side of the engine: the virtual adapter.
type Host interface {
	// WritePacket delivers an IPv4 packet to the OS. pkt is not retained.
	WritePacket(pkt []byte) error
	// SetAddress assigns the adapter its virtual address.
	SetAddress(prefix netip.Prefix) error
}

type Engine struct {
	cfg  Config
	host Host
	log  *log.Logger
	t0   time.Time

	// Set once in Run before any packet flows.
	inv  proto.Invite
	keys *proto.Keys
	udp  *net.UDPConn

	mu        sync.Mutex
	state     string
	message   string
	ip        netip.Addr
	session   [proto.SessionLen]byte
	hasSess   bool
	sharePort int // coordinator's shared-files HTTP port, from the welcome
	serverUDP netip.AddrPort
	lastReg   time.Time
	lastAck   time.Time
	peers     map[netip.Addr]*peer

	noDirect bool           // tests: force everything through the relay
	bind     netip.AddrPort // tests: UDP bind address (default: all interfaces)
}

type peer struct {
	ip         netip.Addr
	name       string
	online     bool
	candidates []netip.AddrPort
	direct     netip.AddrPort // endpoint that last answered a probe
	directSeen time.Time
	rtt        time.Duration
	relayRTT   time.Duration
	punchUntil time.Time
	nextProbe  time.Time
}

// Connection states reported by Status.
const (
	StateStarting   = "starting"
	StateConnecting = "connecting"
	StateOnline     = "online"
	StateError      = "error"
)

func New(cfg Config, host Host, logger *log.Logger) *Engine {
	return &Engine{
		cfg: cfg, host: host, log: logger, t0: time.Now(),
		state: StateStarting, peers: map[netip.Addr]*peer{},
	}
}

// Run connects and keeps the engine running until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	inv, err := proto.ParseInvite(e.cfg.Invite)
	if err != nil {
		e.setState(StateError, err.Error())
		return err
	}
	keys, err := inv.Keys()
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.inv = inv
	e.mu.Unlock()
	udp, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(e.bind))
	if err != nil {
		return fmt.Errorf("open UDP socket: %w", err)
	}
	udp.SetReadBuffer(4 << 20)
	udp.SetWriteBuffer(4 << 20)
	e.keys, e.udp = keys, udp

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); e.readLoop() }()
	go func() { defer wg.Done(); e.tickLoop(ctx) }()

	e.controlLoop(ctx)
	udp.Close()
	wg.Wait()
	return nil
}

// HandleOutbound routes a packet the OS sent to the virtual adapter.
// pkt is not retained.
func (e *Engine) HandleOutbound(pkt []byte) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return // IPv4 only
	}
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))

	type target struct {
		ip   netip.Addr
		addr netip.AddrPort
	}
	var buf [1]target
	targets := buf[:0]

	e.mu.Lock()
	me := e.ip
	if !me.IsValid() || src != me {
		e.mu.Unlock()
		return
	}
	if dst == proto.Broadcast || dst == proto.LimitedBroadcast || dst.IsMulticast() {
		// LAN game discovery: give every peer its own copy.
		for _, p := range e.peers {
			if p.online {
				if a := e.pathLocked(p); a.IsValid() {
					targets = append(targets, target{p.ip, a})
				}
			}
		}
	} else if p := e.peers[dst]; p != nil && p.online {
		if a := e.pathLocked(p); a.IsValid() {
			targets = append(targets, target{p.ip, a})
		}
	}
	e.mu.Unlock()

	for _, t := range targets {
		e.udp.WriteToUDPAddrPort(e.keys.Seal(proto.TypeData, t.ip, me, pkt), t.addr)
	}
}

// pathLocked picks the direct endpoint when it is alive, else the relay.
func (e *Engine) pathLocked(p *peer) netip.AddrPort {
	if p.direct.IsValid() && time.Since(p.directSeen) < directTimeout {
		return p.direct
	}
	return e.serverUDP
}

func (e *Engine) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, from, err := e.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue // e.g. ICMP port unreachable surfacing on Windows
		}
		if n == 0 {
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		e.handleUDP(buf[:n], from)
	}
}

func (e *Engine) handleUDP(pkt []byte, from netip.AddrPort) {
	if pkt[0] == proto.TypeRegisterAck {
		e.mu.Lock()
		if from == e.serverUDP {
			e.lastAck = time.Now()
		}
		e.mu.Unlock()
		return
	}
	typ, dst, src, payload, err := e.keys.Open(pkt)
	if err != nil {
		return
	}

	now := time.Now()
	e.mu.Lock()
	me := e.ip
	p := e.peers[src]
	if p == nil || dst != me {
		e.mu.Unlock()
		return
	}
	viaRelay := from == e.serverUDP
	switch {
	case typ == proto.TypePong && len(payload) == 8:
		rtt := time.Duration(e.since() - int64(binary.BigEndian.Uint64(payload)))
		if viaRelay {
			p.relayRTT = rtt
		} else if !e.noDirect {
			alive := p.direct.IsValid() && now.Sub(p.directSeen) < directTimeout
			if !alive || from == p.direct || rtt < p.rtt {
				if p.direct != from {
					e.log.Printf("direct path to %s (%s) via %s, %s", p.name, p.ip, from, rtt.Round(time.Millisecond))
				}
				p.direct, p.rtt = from, rtt
			}
			if from == p.direct {
				p.directSeen = now
			}
		}
	case !viaRelay && from == p.direct:
		p.directSeen = now
	}
	e.mu.Unlock()

	switch typ {
	case proto.TypePing:
		if len(payload) == 8 && (viaRelay || !e.noDirect) {
			e.udp.WriteToUDPAddrPort(e.keys.Seal(proto.TypePong, src, me, payload), from)
		}
	case proto.TypeData:
		if validInbound(payload, src, me) {
			if err := e.host.WritePacket(payload); err != nil {
				e.log.Printf("write to adapter: %v", err)
			}
		}
	}
}

// validInbound checks that a decrypted packet is IPv4 from the peer that sent
// it, addressed to us or to everyone.
func validInbound(pkt []byte, from, me netip.Addr) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || int(pkt[0]&0x0f)*4 > len(pkt) {
		return false
	}
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	return src == from &&
		(dst == me || dst == proto.Broadcast || dst == proto.LimitedBroadcast || dst.IsMulticast())
}

func (e *Engine) since() int64 { return int64(time.Since(e.t0)) }

// tickLoop keeps the coordinator registration and peer paths alive.
func (e *Engine) tickLoop(ctx context.Context) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		e.tick(time.Now())
	}
}

func (e *Engine) tick(now time.Time) {
	type probe struct {
		ip   netip.Addr
		addr netip.AddrPort
	}
	var probes []probe
	var reg []byte

	e.mu.Lock()
	me, srv := e.ip, e.serverUDP
	if e.hasSess && srv.IsValid() {
		every := registerEvery
		if now.Sub(e.lastAck) > registerEvery+5*time.Second {
			every = registerRetry
		}
		if now.Sub(e.lastReg) >= every {
			e.lastReg = now
			reg = append([]byte{proto.TypeRegister}, e.session[:]...)
		}
	}
	if me.IsValid() && srv.IsValid() {
		for _, p := range e.peers {
			if !p.online || now.Before(p.nextProbe) {
				continue
			}
			directOK := p.direct.IsValid() && now.Sub(p.directSeen) < directTimeout
			switch {
			case directOK:
				p.nextProbe = now.Add(keepalive)
				probes = append(probes, probe{p.ip, p.direct})
			default:
				if now.Before(p.punchUntil) {
					p.nextProbe = now.Add(punchFast)
				} else {
					p.nextProbe = now.Add(punchSlow)
				}
				// Probe the relay for an RTT, and every candidate to punch through.
				probes = append(probes, probe{p.ip, srv})
				if !e.noDirect {
					for _, c := range p.candidates {
						probes = append(probes, probe{p.ip, c})
					}
				}
			}
		}
	}
	e.mu.Unlock()

	if reg != nil {
		e.udp.WriteToUDPAddrPort(reg, srv)
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(e.since()))
	for _, pr := range probes {
		e.udp.WriteToUDPAddrPort(e.keys.Seal(proto.TypePing, pr.ip, me, ts[:]), pr.addr)
	}
}

func (e *Engine) controlLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		e.mu.Lock()
		if e.state != StateError { // keep a refusal visible while retrying
			e.state, e.message = StateConnecting, ""
		}
		e.mu.Unlock()
		start := time.Now()
		err := e.runSession(ctx)
		if ctx.Err() != nil {
			return
		}
		wait := backoff
		var refused refusedError
		if errors.As(err, &refused) {
			e.setState(StateError, refused.msg)
			wait = refusedBackoff
		} else {
			e.setState(StateConnecting, fmt.Sprintf("lost connection to coordinator: %v", err))
		}
		e.log.Printf("control: %v (retrying in %s)", err, wait)
		if time.Since(start) > time.Minute {
			backoff = time.Second
		} else {
			backoff = min(backoff*2, maxBackoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

type refusedError struct{ msg string }

func (r refusedError) Error() string { return "coordinator refused: " + r.msg }

// runSession runs one control connection to the coordinator.
func (e *Engine) runSession(ctx context.Context) error {
	addr := e.cfg.Server
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, strconv.Itoa(proto.DefaultPort))
	}
	d := net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	// The relay listens on the same address as the control connection.
	srv := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
	srv = netip.AddrPortFrom(srv.Addr().Unmap(), srv.Port())

	var wmu sync.Mutex
	send := func(m *proto.Msg) error {
		b, _ := json.Marshal(m)
		wmu.Lock()
		defer wmu.Unlock()
		conn.SetWriteDeadline(time.Now().Add(dialTimeout))
		_, err := conn.Write(append(b, '\n'))
		return err
	}
	if err := send(&proto.Msg{
		Type: proto.MsgJoin, Version: proto.Version, Network: e.keys.NetworkID, Label: e.inv.Label, Auth: e.keys.Auth,
		Device: e.cfg.DeviceID, Name: e.cfg.Name, Local: e.localEndpoints(),
	}); err != nil {
		return err
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(ctrlPing)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if send(&proto.Msg{Type: proto.MsgPing}) != nil {
					conn.Close()
					return
				}
			}
		}
	}()

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 4096), 1<<20)
	for {
		conn.SetReadDeadline(time.Now().Add(readTimeout))
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				return err
			}
			return errors.New("connection closed")
		}
		var m proto.Msg
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			return err
		}
		switch m.Type {
		case proto.MsgError:
			return refusedError{m.Error}
		case proto.MsgWelcome:
			if err := e.welcome(&m, srv); err != nil {
				return err
			}
		case proto.MsgPeers:
			e.updatePeers(m.Peers)
		}
	}
}

func (e *Engine) welcome(m *proto.Msg, srv netip.AddrPort) error {
	ip, err := netip.ParseAddr(m.IP)
	if err != nil || !proto.Subnet.Contains(ip) {
		return fmt.Errorf("coordinator assigned invalid address %q", m.IP)
	}
	sess, err := hex.DecodeString(m.Session)
	if err != nil || len(sess) != proto.SessionLen {
		return errors.New("coordinator sent invalid session")
	}

	e.mu.Lock()
	changed := ip != e.ip
	e.mu.Unlock()
	if changed {
		if err := e.host.SetAddress(netip.PrefixFrom(ip, proto.Subnet.Bits())); err != nil {
			return fmt.Errorf("configure adapter: %w", err)
		}
	}

	e.mu.Lock()
	e.ip = ip
	e.session = [proto.SessionLen]byte(sess)
	e.sharePort = m.SharePort
	e.hasSess = true
	e.serverUDP = srv
	e.lastReg, e.lastAck = time.Time{}, time.Time{}
	e.state, e.message = StateOnline, ""
	e.mu.Unlock()
	e.log.Printf("online as %s in %q", ip, e.inv.Label)
	e.tick(time.Now()) // register right away
	return nil
}

func (e *Engine) updatePeers(list []proto.PeerInfo) {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	seen := map[netip.Addr]bool{}
	for _, pi := range list {
		ip, err := netip.ParseAddr(pi.IP)
		if err != nil || ip == e.ip || !proto.Subnet.Contains(ip) {
			continue
		}
		seen[ip] = true
		p := e.peers[ip]
		if p == nil {
			p = &peer{ip: ip}
			e.peers[ip] = p
		}
		var cands []netip.AddrPort
		for _, s := range append([]string{pi.Public}, pi.Local...) {
			if ap, err := netip.ParseAddrPort(s); err == nil && usableEndpoint(ap) && !slices.Contains(cands, ap) {
				cands = append(cands, ap)
			}
		}
		if (pi.Online && !p.online) || !slices.Equal(cands, p.candidates) {
			p.punchUntil = now.Add(punchFastFor)
			p.nextProbe = time.Time{}
		}
		if !pi.Online {
			p.direct, p.directSeen = netip.AddrPort{}, time.Time{}
		}
		p.name, p.online, p.candidates = pi.Name, pi.Online, cands
	}
	for ip := range e.peers {
		if !seen[ip] {
			delete(e.peers, ip)
		}
	}
}

func usableEndpoint(ap netip.AddrPort) bool {
	a := ap.Addr()
	return ap.Port() != 0 && a.Is4() && !a.IsUnspecified() && !a.IsMulticast() &&
		!proto.Subnet.Contains(a) && a != proto.LimitedBroadcast
}

// localEndpoints lists this machine's LAN addresses with our UDP port, so
// friends on the same LAN can connect without going out to the internet.
func (e *Engine) localEndpoints() []string {
	if e.bind.Addr().IsLoopback() {
		return nil
	}
	port := e.udp.LocalAddr().(*net.UDPAddr).Port
	addrs, _ := net.InterfaceAddrs()
	var out []string
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		ip = ip.Unmap()
		if !ok || !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || proto.Subnet.Contains(ip) {
			continue
		}
		out = append(out, netip.AddrPortFrom(ip, uint16(port)).String())
		if len(out) == 8 {
			break
		}
	}
	return out
}

func (e *Engine) setState(state, msg string) {
	e.mu.Lock()
	e.state, e.message = state, msg
	e.mu.Unlock()
}

// Status is a snapshot for the local UI.
type Status struct {
	State   string       `json:"state"`
	Message string       `json:"message,omitempty"`
	IP      string       `json:"ip,omitempty"`
	Name    string       `json:"name"`
	Network string       `json:"network"` // the invite's label, e.g. "blur"
	Invite  string       `json:"invite"`  // full invite code, to share with friends
	Server  string       `json:"server"`
	Relay   bool         `json:"relay"` // UDP registration with the coordinator is working
	Peers   []PeerStatus `json:"peers"`
}

type PeerStatus struct {
	Name     string  `json:"name"`
	IP       string  `json:"ip"`
	Online   bool    `json:"online"`
	Path     string  `json:"path"` // "direct", "relay" or "offline"
	RTTms    float64 `json:"rttMs"`
	Endpoint string  `json:"endpoint,omitempty"`
}

func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	st := Status{
		State: e.state, Message: e.message, Name: e.cfg.Name, Server: e.cfg.Server,
		Relay: !e.lastAck.IsZero() && now.Sub(e.lastAck) < 3*registerEvery,
		Peers: []PeerStatus{},
	}
	if e.inv.Secret != "" {
		st.Network, st.Invite = e.inv.Label, e.inv.String()
	}
	if e.ip.IsValid() {
		st.IP = e.ip.String()
	}
	for _, p := range e.peers {
		ps := PeerStatus{Name: p.name, IP: p.ip.String(), Online: p.online, Path: "offline", RTTms: -1}
		if p.online {
			if p.direct.IsValid() && now.Sub(p.directSeen) < directTimeout {
				ps.Path, ps.Endpoint = "direct", p.direct.String()
				ps.RTTms = ms(p.rtt)
			} else {
				ps.Path = "relay"
				if p.relayRTT > 0 {
					ps.RTTms = ms(p.relayRTT)
				}
			}
		}
		st.Peers = append(st.Peers, ps)
	}
	sort.Slice(st.Peers, func(i, j int) bool {
		return netip.MustParseAddr(st.Peers[i].IP).Less(netip.MustParseAddr(st.Peers[j].IP))
	})
	return st
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
