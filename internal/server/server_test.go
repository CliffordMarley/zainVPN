package server

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"zainvpn/internal/proto"
)

const msgTimeout = 5 * time.Second

// Auth tokens for two different passwords. The server only checks length and
// hash, so tests don't need the (slow) real key derivation.
var (
	authA = strings.Repeat("a1", proto.AuthLen/2)
	authB = strings.Repeat("b2", proto.AuthLen/2)
)

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// testLogger collects server logs and prints them only if the test fails.
// Server goroutines can outlive the test, so they must not call t.Log.
func testLogger(t *testing.T) *log.Logger {
	l := &logBuf{}
	t.Cleanup(func() {
		if t.Failed() {
			l.mu.Lock()
			t.Logf("server log:\n%s", l.b.String())
			l.mu.Unlock()
		}
	})
	return log.New(l, "", log.Lmicroseconds)
}

type testServer struct {
	*Server
	addr netip.AddrPort // TCP control and UDP relay share it
	stop func()         // closes the listeners; existing connections stay up
}

func startServer(t *testing.T, statePath string) *testServer {
	t.Helper()
	s, err := New(statePath, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	ln, udp := listenPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.Serve(ln, udp); err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			ln.Close()
			udp.Close()
			<-done
			// Clients close their side in their own (earlier-running) cleanups.
			// Wait for the handlers' leave, which saves state, so nothing writes
			// into the test's temp dir while it is being removed.
			deadline := time.Now().Add(msgTimeout)
			for online(s) > 0 {
				if time.Now().After(deadline) {
					t.Errorf("%d members still online after stop", online(s))
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
	t.Cleanup(stop)
	ap := ln.Addr().(*net.TCPAddr).AddrPort()
	return &testServer{s, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), stop}
}

func online(s *Server) int {
	n := 0
	for _, nw := range s.Snapshot().Networks {
		n += nw.Online
	}
	return n
}

// listenPair opens TCP and UDP on the same loopback port, like the real
// coordinator, retrying if the UDP port happens to be taken.
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

// rawClient speaks the control protocol and the UDP side by hand.
type rawClient struct {
	t       *testing.T
	ts      *testServer
	conn    net.Conn
	msgs    chan proto.Msg // closed when the server closes the connection
	ip      string
	session []byte
	udp     *net.UDPConn
}

func dial(t *testing.T, ts *testServer) *rawClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", ts.addr.String(), msgTimeout)
	if err != nil {
		t.Fatal(err)
	}
	c := &rawClient{t: t, ts: ts, conn: conn, msgs: make(chan proto.Msg, 64)}
	quit := make(chan struct{})
	t.Cleanup(func() {
		close(quit)
		conn.Close()
		if c.udp != nil {
			c.udp.Close()
		}
	})
	go func() {
		defer close(c.msgs)
		sc := bufio.NewScanner(conn)
		sc.Buffer(make([]byte, 4096), 1<<20)
		for sc.Scan() {
			var m proto.Msg
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				m = proto.Msg{Type: "invalid JSON: " + sc.Text()}
			}
			select {
			case c.msgs <- m:
			case <-quit:
				return
			}
		}
	}()
	return c
}

// join sends a join message; follow it with welcome() or refused().
func join(t *testing.T, ts *testServer, network, auth, device, name string, local ...string) *rawClient {
	t.Helper()
	c := dial(t, ts)
	c.send(proto.Msg{
		Type: proto.MsgJoin, Version: proto.Version, Network: network, Auth: auth,
		Device: device, Name: name, Local: local,
	})
	return c
}

func mustJoin(t *testing.T, ts *testServer, network, auth, device, name string, local ...string) *rawClient {
	t.Helper()
	return join(t, ts, network, auth, device, name, local...).welcome()
}

func (c *rawClient) send(m proto.Msg) {
	c.t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		c.t.Fatal(err)
	}
	c.sendRaw(append(b, '\n'))
}

func (c *rawClient) sendRaw(b []byte) {
	c.t.Helper()
	c.conn.SetWriteDeadline(time.Now().Add(msgTimeout))
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

// next returns the next control message; ok is false once the server has
// closed the connection.
func (c *rawClient) next(deadline time.Time) (m proto.Msg, ok bool) {
	c.t.Helper()
	select {
	case m, ok = <-c.msgs:
		return m, ok
	case <-time.After(time.Until(deadline)):
		c.t.Fatal("timed out waiting for a control message")
		return m, false
	}
}

func (c *rawClient) welcome() *rawClient {
	c.t.Helper()
	deadline := time.Now().Add(msgTimeout)
	for {
		m, ok := c.next(deadline)
		switch {
		case !ok:
			c.t.Fatal("connection closed before welcome")
		case m.Type == proto.MsgPeers:
			continue // another member's broadcast can overtake the welcome
		case m.Type != proto.MsgWelcome:
			c.t.Fatalf("got %+v, want welcome", m)
		}
		sess, err := hex.DecodeString(m.Session)
		if err != nil || len(sess) != proto.SessionLen {
			c.t.Fatalf("bad session %q", m.Session)
		}
		c.ip, c.session = m.IP, sess
		return c
	}
}

// refused expects an error message, then the server closing the connection.
func (c *rawClient) refused() string {
	c.t.Helper()
	m, ok := c.next(time.Now().Add(msgTimeout))
	if !ok || m.Type != proto.MsgError || m.Error == "" {
		c.t.Fatalf("got %+v (open %v), want an error message", m, ok)
	}
	if m, ok := c.next(time.Now().Add(msgTimeout)); ok {
		c.t.Fatalf("got %+v after the error, want the connection closed", m)
	}
	return m.Error
}

// closed waits for the server to close the connection, skipping peer lists.
func (c *rawClient) closed() {
	c.t.Helper()
	deadline := time.Now().Add(msgTimeout)
	for {
		m, ok := c.next(deadline)
		if !ok {
			return
		}
		if m.Type != proto.MsgPeers {
			c.t.Fatalf("got %+v, want the connection closed", m)
		}
	}
}

// peersUntil reads peer lists until one satisfies cond and returns it.
func (c *rawClient) peersUntil(desc string, cond func([]proto.PeerInfo) bool) []proto.PeerInfo {
	c.t.Helper()
	deadline := time.Now().Add(msgTimeout)
	for {
		m, ok := c.next(deadline)
		if !ok {
			c.t.Fatalf("connection closed while waiting for peers: %s", desc)
		}
		if m.Type == proto.MsgPeers && cond(m.Peers) {
			return m.Peers
		}
	}
}

func findPeer(peers []proto.PeerInfo, ip string) *proto.PeerInfo {
	for i := range peers {
		if peers[i].IP == ip {
			return &peers[i]
		}
	}
	return nil
}

// isOnline reports whether p is an online, not yet registered member.
func isOnline(p proto.PeerInfo, ip, name string) bool {
	return p.IP == ip && p.Name == name && p.Online && p.Public == "" && len(p.Local) == 0
}

func newUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	return u
}

// register sends the session over UDP (opening a socket if needed) until acked.
func (c *rawClient) register() {
	c.t.Helper()
	if c.udp == nil {
		c.udp = newUDP(c.t)
	}
	if !tryRegister(c.udp, c.ts.addr, c.session, 5) {
		c.t.Fatal("no register ack")
	}
}

func tryRegister(u *net.UDPConn, srv netip.AddrPort, session []byte, attempts int) bool {
	reg := append([]byte{proto.TypeRegister}, session...)
	buf := make([]byte, 64)
	for range attempts {
		u.WriteToUDPAddrPort(reg, srv)
		u.SetReadDeadline(time.Now().Add(time.Second))
		for {
			n, from, err := u.ReadFromUDPAddrPort(buf)
			if err != nil {
				break
			}
			if n == 1 && buf[0] == proto.TypeRegisterAck && unmap(from) == srv {
				return true
			}
		}
	}
	return false
}

// expectNoAck checks that a register attempt is ignored.
func expectNoAck(t *testing.T, u *net.UDPConn, srv netip.AddrPort, session []byte) {
	t.Helper()
	reg := append([]byte{proto.TypeRegister}, session...)
	u.WriteToUDPAddrPort(reg, srv)
	u.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 64)
	if n, _, err := u.ReadFromUDPAddrPort(buf); err == nil {
		t.Fatalf("got % x in reply to an invalid registration", buf[:n])
	}
}

func (c *rawClient) public() string { return c.udp.LocalAddr().String() }

func (c *rawClient) sendUDP(pkt []byte) {
	c.t.Helper()
	if _, err := c.udp.WriteToUDPAddrPort(pkt, c.ts.addr); err != nil {
		c.t.Fatal(err)
	}
}

// recvUDP returns the next relayed packet, skipping stray register acks.
func (c *rawClient) recvUDP() []byte {
	c.t.Helper()
	buf := make([]byte, 2048)
	c.udp.SetReadDeadline(time.Now().Add(msgTimeout))
	for {
		n, _, err := c.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			c.t.Fatalf("waiting for a relayed packet: %v", err)
		}
		if n != 1 || buf[0] != proto.TypeRegisterAck {
			return bytes.Clone(buf[:n])
		}
	}
}

// peerPacket builds a peer packet; the relay only looks at the header and length.
func peerPacket(typ byte, dst, src, body string) []byte {
	pkt := make([]byte, proto.Overhead, proto.Overhead+len(body))
	pkt[0] = typ
	d, s := netip.MustParseAddr(dst).As4(), netip.MustParseAddr(src).As4()
	copy(pkt[1:5], d[:])
	copy(pkt[5:9], s[:])
	return append(pkt, body...)
}

func waitFor(t *testing.T, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(msgTimeout)
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

func findNetwork(snap Snapshot, name string) *NetworkInfo {
	for i := range snap.Networks {
		if snap.Networks[i].Name == name {
			return &snap.Networks[i]
		}
	}
	return nil
}

func waitOnline(t *testing.T, ts *testServer, network string, want int) {
	t.Helper()
	waitFor(t, func() error {
		nw := findNetwork(ts.Snapshot(), network)
		if nw == nil || nw.Online != want {
			return fmt.Errorf("network %q: %+v, want %d online", network, nw, want)
		}
		return nil
	})
}

func TestJoinAssignsAddresses(t *testing.T) {
	ts := startServer(t, "")
	a := mustJoin(t, ts, "LAN Party", authA, "dev-a", "Alice")
	if a.ip != "10.77.0.1" {
		t.Fatalf("first device got %s, want 10.77.0.1", a.ip)
	}
	a.peersUntil("alice listed", func(p []proto.PeerInfo) bool {
		return len(p) == 1 && isOnline(p[0], "10.77.0.1", "Alice")
	})

	b := mustJoin(t, ts, "  lan PARTY ", authA, "dev-b", "Bob")
	if b.ip != "10.77.0.2" {
		t.Fatalf("second device got %s, want 10.77.0.2", b.ip)
	}
	if bytes.Equal(a.session, b.session) {
		t.Error("two members got the same session")
	}
	both := func(p []proto.PeerInfo) bool {
		return len(p) == 2 && isOnline(p[0], "10.77.0.1", "Alice") && isOnline(p[1], "10.77.0.2", "Bob")
	}
	a.peersUntil("alice sees bob", both)
	b.peersUntil("bob sees both", both)

	// Every network has its own address space, even for the same device ID.
	c := mustJoin(t, ts, "other", authB, "dev-a", "Alice")
	if c.ip != "10.77.0.1" {
		t.Errorf("first device in another network got %s, want 10.77.0.1", c.ip)
	}
	c.peersUntil("only alice in other", func(p []proto.PeerInfo) bool { return len(p) == 1 })

	snap := ts.Snapshot()
	if len(snap.Networks) != 2 || snap.Networks[0].Name != "lan party" || snap.Networks[0].Online != 2 ||
		snap.Networks[1].Name != "other" || snap.Networks[1].Online != 1 {
		t.Errorf("snapshot networks = %+v", snap.Networks)
	}
}

func TestJoinLabel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	ts := startServer(t, path)
	// Invite networks are known by an opaque ID; the label is for display only.
	id := strings.Repeat("0f", 16)
	joinLabel := func(ts *testServer, network, label, auth, device string) *rawClient {
		c := dial(t, ts)
		c.send(proto.Msg{
			Type: proto.MsgJoin, Version: proto.Version, Network: network, Label: label, Auth: auth,
			Device: device, Name: device,
		})
		return c
	}
	a := joinLabel(ts, id, "Blur Night!", authA, "dev-a").welcome()
	// The label is cleaned, and set once: later joins can't rename the network.
	b := joinLabel(ts, id, "pwned", authA, "dev-b").welcome()
	if a.ip != "10.77.0.1" || b.ip != "10.77.0.2" {
		t.Errorf("got %s and %s", a.ip, b.ip)
	}
	// Legacy clients send no label.
	c := mustJoin(t, ts, "LAN", authB, "dev-c", "Carol")
	// A refused join doesn't touch the label either.
	if msg := joinLabel(ts, id, "other", authB, "dev-m").refused(); !strings.Contains(msg, "password") {
		t.Errorf("wrong auth for a labelled network: %q", msg)
	}
	long := joinLabel(ts, strings.Repeat("1e", 16), "<b>"+strings.Repeat("x", 40), authB, "dev-l").welcome()
	if long.ip != "10.77.0.1" {
		t.Errorf("first device in a new network got %s", long.ip)
	}

	check := func(snap Snapshot) {
		t.Helper()
		want := map[string]string{id: "blur-night", "lan": "", strings.Repeat("1e", 16): "b" + strings.Repeat("x", 19)}
		if len(snap.Networks) != len(want) {
			t.Fatalf("networks = %+v", snap.Networks)
		}
		for _, nw := range snap.Networks {
			if l, ok := want[nw.Name]; !ok || nw.Label != l {
				t.Errorf("network %q has label %q, want %q", nw.Name, nw.Label, l)
			}
		}
	}
	check(ts.Snapshot())
	js, err := json.Marshal(ts.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(js, []byte(`"label":`)) != 2 {
		t.Errorf("want a label only on the two invite networks:\n%s", js)
	}

	// Labels survive a restart.
	for _, c := range []*rawClient{a, b, c, long} {
		c.conn.Close()
	}
	for _, nw := range ts.Snapshot().Networks {
		waitOnline(t, ts, nw.Name, 0)
	}
	ts.stop()
	ts2 := startServer(t, path)
	check(ts2.Snapshot())
	if c := joinLabel(ts2, id, "", authA, "dev-a").welcome(); c.ip != "10.77.0.1" {
		t.Errorf("rejoin without a label got %s", c.ip)
	}
	if nw := findNetwork(ts2.Snapshot(), id); nw.Label != "blur-night" {
		t.Errorf("label after a join without one = %q", nw.Label)
	}
}

func TestRejoinKeepsAddress(t *testing.T) {
	ts := startServer(t, "")
	a := mustJoin(t, ts, "lan", authA, "dev-a", "Alice")
	b := mustJoin(t, ts, "lan", authA, "dev-b", "Bob")
	if a.ip != "10.77.0.1" || b.ip != "10.77.0.2" {
		t.Fatalf("got %s and %s", a.ip, b.ip)
	}

	a.conn.Close()
	b.peersUntil("alice offline", func(p []proto.PeerInfo) bool {
		pa := findPeer(p, "10.77.0.1")
		return len(p) == 2 && pa != nil && !pa.Online
	})
	a2 := mustJoin(t, ts, "lan", authA, "dev-a", "Alice 2")
	if a2.ip != "10.77.0.1" {
		t.Fatalf("rejoining device got %s, want 10.77.0.1", a2.ip)
	}
	b.peersUntil("alice back under her new name", func(p []proto.PeerInfo) bool {
		pa := findPeer(p, "10.77.0.1")
		return pa != nil && pa.Online && pa.Name == "Alice 2"
	})

	// Joining again while still connected replaces the old connection.
	a3 := mustJoin(t, ts, "LAN", authA, "dev-a", "Alice 3")
	if a3.ip != "10.77.0.1" {
		t.Fatalf("replacing connection got %s, want 10.77.0.1", a3.ip)
	}
	a2.closed()

	c := mustJoin(t, ts, "lan", authA, "dev-c", "Carol")
	if c.ip != "10.77.0.3" {
		t.Errorf("new device got %s, want 10.77.0.3", c.ip)
	}
	waitOnline(t, ts, "lan", 3)
	if nw := findNetwork(ts.Snapshot(), "lan"); len(nw.Devices) != 3 {
		t.Errorf("devices = %+v, want 3", nw.Devices)
	}
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "state.json")
	ts := startServer(t, path)
	a := mustJoin(t, ts, "LAN", authA, "dev-a", "Alice")
	b := mustJoin(t, ts, "lan", authA, "dev-b", "Bob")
	a.conn.Close()
	b.conn.Close()
	waitOnline(t, ts, "lan", 0) // leave saves state before it drops the member
	before := ts.Snapshot()
	ts.stop()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(authA)) || !bytes.Contains(data, []byte(proto.AuthHash(authA))) {
		t.Errorf("state file should hold the auth hash, not the token:\n%s", data)
	}

	ts2 := startServer(t, path)
	snap := ts2.Snapshot()
	if len(snap.Networks) != 1 {
		t.Fatalf("networks after restart = %+v", snap.Networks)
	}
	nw, old := snap.Networks[0], before.Networks[0]
	if nw.Name != "lan" || nw.Online != 0 || !nw.Created.Equal(old.Created) || len(nw.Devices) != 2 {
		t.Fatalf("network after restart = %+v, before = %+v", nw, old)
	}
	for i, d := range nw.Devices {
		o := old.Devices[i]
		if d.ID != o.ID || d.IP != o.IP || d.Name != o.Name || d.Online || !d.LastSeen.Equal(o.LastSeen) {
			t.Errorf("device after restart = %+v, before = %+v", d, o)
		}
	}

	if b2 := mustJoin(t, ts2, "lan", authA, "dev-b", "Bob"); b2.ip != "10.77.0.2" {
		t.Errorf("bob got %s after restart, want 10.77.0.2", b2.ip)
	}
	if c := mustJoin(t, ts2, "lan", authA, "dev-c", "Carol"); c.ip != "10.77.0.3" {
		t.Errorf("new device got %s after restart, want 10.77.0.3", c.ip)
	}
	if msg := join(t, ts2, "lan", authB, "dev-m", "Mallory").refused(); !strings.Contains(msg, "password") {
		t.Errorf("wrong password after restart: %q", msg)
	}
}

func TestCorruptStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path, testLogger(t)); err == nil {
		t.Error("New accepted a corrupt state file")
	}
}

func TestWrongPasswordRefused(t *testing.T) {
	ts := startServer(t, "")
	a := mustJoin(t, ts, "lan", authA, "dev-a", "Alice")
	start := time.Now()
	msg := join(t, ts, "LAN", authB, "dev-m", "Mallory").refused()
	if !strings.Contains(msg, "password") {
		t.Errorf("refusal %q doesn't mention the password", msg)
	}
	if d := time.Since(start); d < 900*time.Millisecond {
		t.Errorf("wrong password refused after %s, want a ~1s delay", d)
	}
	// The same device ID with the wrong password doesn't take over the device either.
	if msg := join(t, ts, "lan", authB, "dev-a", "Mallory").refused(); !strings.Contains(msg, "password") {
		t.Errorf("refusal %q doesn't mention the password", msg)
	}
	nw := findNetwork(ts.Snapshot(), "lan")
	if nw == nil || nw.Online != 1 || len(nw.Devices) != 1 || nw.Devices[0].Name != "Alice" {
		t.Errorf("network = %+v", nw)
	}
	a.send(proto.Msg{Type: proto.MsgPing})
	for {
		m, ok := a.next(time.Now().Add(msgTimeout))
		if !ok {
			t.Fatal("alice was disconnected")
		}
		if m.Type == proto.MsgPong {
			break
		}
	}
}

func TestJoinValidation(t *testing.T) {
	ts := startServer(t, "")
	ok := proto.Msg{Type: proto.MsgJoin, Version: proto.Version, Network: "lan", Auth: authA, Device: "dev", Name: "n"}
	for _, tc := range []struct {
		name   string
		mutate func(*proto.Msg)
		want   string
	}{
		{"no version", func(m *proto.Msg) { m.Version = 0 }, "version"},
		{"newer version", func(m *proto.Msg) { m.Version = proto.Version + 1 }, "version"},
		{"empty network", func(m *proto.Msg) { m.Network = "" }, "network"},
		{"blank network", func(m *proto.Msg) { m.Network = " \t " }, "network"},
		{"long network", func(m *proto.Msg) { m.Network = strings.Repeat("n", 65) }, "network"},
		{"no auth", func(m *proto.Msg) { m.Auth = "" }, "credentials"},
		{"short auth", func(m *proto.Msg) { m.Auth = authA[:proto.AuthLen-1] }, "credentials"},
		{"long auth", func(m *proto.Msg) { m.Auth = authA + "0" }, "credentials"},
		{"no device", func(m *proto.Msg) { m.Device = "" }, "device"},
		{"long device", func(m *proto.Msg) { m.Device = strings.Repeat("d", 65) }, "device"},
	} {
		msg := ok
		tc.mutate(&msg)
		c := dial(t, ts)
		c.send(msg)
		if got := c.refused(); !strings.Contains(got, tc.want) {
			t.Errorf("%s: refusal %q doesn't mention %q", tc.name, got, tc.want)
		}
	}

	// Anything other than a join as the first line just gets disconnected.
	for name, line := range map[string]string{
		"ping first": `{"type":"ping"}`,
		"garbage":    `hello`,
		"wrong type": `{"type":"welcome","ip":"10.77.0.1"}`,
	} {
		c := dial(t, ts)
		c.sendRaw([]byte(line + "\n"))
		if m, ok := c.next(time.Now().Add(msgTimeout)); ok {
			t.Errorf("%s: got %+v, want the connection closed", name, m)
		}
	}
	if snap := ts.Snapshot(); len(snap.Networks) != 0 {
		t.Fatalf("refused joins created networks: %+v", snap.Networks)
	}

	// Limits are inclusive.
	long := ok
	long.Network, long.Device = strings.Repeat("n", 64), strings.Repeat("d", 64)
	c := dial(t, ts)
	c.send(long)
	if c.welcome(); c.ip != "10.77.0.1" {
		t.Errorf("got %s", c.ip)
	}
}

func TestRegisterPublishesEndpoint(t *testing.T) {
	ts := startServer(t, "")
	a := mustJoin(t, ts, "lan", authA, "dev-a", "Alice", "192.168.1.10:40000")
	b := mustJoin(t, ts, "lan", authA, "dev-b", "Bob")
	a.register()
	peers := b.peersUntil("alice's public endpoint", func(p []proto.PeerInfo) bool {
		pa := findPeer(p, a.ip)
		return pa != nil && pa.Public == a.public()
	})
	if pa, pb := findPeer(peers, a.ip), findPeer(peers, b.ip); !slices.Equal(pa.Local, []string{"192.168.1.10:40000"}) || pb.Public != "" {
		t.Errorf("peers = %+v", peers)
	}
	nw := findNetwork(ts.Snapshot(), "lan")
	if d := nw.Devices[0]; d.ID != "dev-a" || d.Public != a.public() {
		t.Errorf("snapshot device = %+v, want public %s", d, a.public())
	}

	// A new endpoint (e.g. the NAT mapping changed) replaces the old one.
	moved := newUDP(t)
	if !tryRegister(moved, ts.addr, a.session, 5) {
		t.Fatal("no ack from the new endpoint")
	}
	b.peersUntil("alice's new endpoint", func(p []proto.PeerInfo) bool {
		pa := findPeer(p, a.ip)
		return pa != nil && pa.Public == moved.LocalAddr().String()
	})

	// Unknown or malformed sessions are ignored.
	u := newUDP(t)
	expectNoAck(t, u, ts.addr, make([]byte, proto.SessionLen))
	expectNoAck(t, u, ts.addr, a.session[:proto.SessionLen-1])
	expectNoAck(t, u, ts.addr, append(slices.Clone(a.session), 0))
}

func TestRelay(t *testing.T) {
	ts := startServer(t, "")
	a1 := mustJoin(t, ts, "net-a", authA, "a1", "a1")
	a2 := mustJoin(t, ts, "net-a", authA, "a2", "a2")
	a3 := mustJoin(t, ts, "net-a", authA, "a3", "a3")
	a4 := mustJoin(t, ts, "net-a", authA, "a4", "a4") // never registers a UDP endpoint
	b1 := mustJoin(t, ts, "net-b", authB, "b1", "b1")
	b2 := mustJoin(t, ts, "net-b", authB, "b2", "b2")
	for _, c := range []*rawClient{a1, a2, a3, b1, b2} {
		c.register()
	}

	var packets, total, fromA1 uint64
	forward := func(from, to *rawClient, pkt []byte) {
		t.Helper()
		from.sendUDP(pkt)
		if got := to.recvUDP(); !bytes.Equal(got, pkt) {
			t.Fatalf("%s -> %s: got %q, want %q", from.ip, to.ip, got[min(len(got), proto.Overhead):], pkt[proto.Overhead:])
		}
		packets++
		total += uint64(len(pkt))
		if from == a1 {
			fromA1 += uint64(len(pkt))
		}
	}

	// Members of the same network reach each other, verbatim, for every peer packet type.
	forward(a1, a2, peerPacket(proto.TypeData, a2.ip, a1.ip, "data a1->a2"))
	forward(a2, a1, peerPacket(proto.TypeData, a1.ip, a2.ip, "data a2->a1"))
	forward(a1, a3, peerPacket(proto.TypePing, a3.ip, a1.ip, "ping a1->a3"))
	forward(a3, a1, peerPacket(proto.TypePong, a1.ip, a3.ip, "pong a3->a1"))
	forward(b1, b2, peerPacket(proto.TypeData, b2.ip, b1.ip, "data b1->b2"))
	forward(a1, a2, peerPacket(proto.TypeData, a2.ip, a1.ip, string(make([]byte, proto.MTU))))

	// None of these may be forwarded.
	stranger := newUDP(t)
	for _, bad := range []struct {
		from *net.UDPConn
		pkt  []byte
	}{
		{a1.udp, peerPacket(proto.TypeData, a2.ip, a3.ip, "src is another member")},
		{a1.udp, peerPacket(proto.TypeData, a2.ip, "10.77.0.99", "src is nobody")},
		{a1.udp, peerPacket(proto.TypeData, a4.ip, a1.ip, "dst has no UDP endpoint")},
		{a1.udp, peerPacket(proto.TypeData, a1.ip, a1.ip, "dst is the sender")},
		{a1.udp, peerPacket(proto.TypeData, "10.77.0.99", a1.ip, "dst is nobody")},
		{a1.udp, peerPacket(proto.TypeData, a2.ip, a1.ip, "")[:proto.Overhead-1]},
		{a1.udp, peerPacket(0x7f, a2.ip, a1.ip, "unknown type")},
		{a1.udp, peerPacket(proto.TypeRegisterAck, a2.ip, a1.ip, "not a peer packet")},
		{stranger, peerPacket(proto.TypeData, a2.ip, a1.ip, "unregistered sender")},
		{b1.udp, peerPacket(proto.TypeData, a3.ip, b1.ip, "net-b has no 10.77.0.3")},
	} {
		if _, err := bad.from.WriteToUDPAddrPort(bad.pkt, ts.addr); err != nil {
			t.Fatal(err)
		}
	}
	// The server handles packets in order, so if any of the above had been
	// forwarded it would arrive before these.
	forward(a1, a2, peerPacket(proto.TypeData, a2.ip, a1.ip, "sentinel a2"))
	forward(a1, a3, peerPacket(proto.TypeData, a3.ip, a1.ip, "sentinel a3"))
	forward(b1, b2, peerPacket(proto.TypeData, b2.ip, b1.ip, "sentinel b2"))
	forward(b2, b1, peerPacket(proto.TypeData, b1.ip, b2.ip, "sentinel b1"))

	snap := ts.Snapshot()
	if snap.RelayPackets != packets || snap.RelayBytes != total {
		t.Errorf("relay counters = %d packets / %d bytes, want %d / %d", snap.RelayPackets, snap.RelayBytes, packets, total)
	}
	if d := findNetwork(snap, "net-a").Devices[0]; d.ID != "a1" || d.RelayBytes != fromA1 {
		t.Errorf("a1 relay bytes = %+v, want %d", d, fromA1)
	}
}

func TestSnapshot(t *testing.T) {
	ts := startServer(t, "")
	before := time.Now()
	locals := []string{"192.168.1.5:5000", "not an endpoint", "[2001:db8::1]:5000", "10.0.0.7:0"}
	for i := range 10 {
		locals = append(locals, fmt.Sprintf("10.0.1.%d:6000", i+1))
	}
	z := mustJoin(t, ts, "Zeta", authA, "z1", "  Zed\x07\x00 \n", locals...)
	a1 := mustJoin(t, ts, "alpha", authB, "a1", "")
	a2 := mustJoin(t, ts, "alpha", authB, "a2", strings.Repeat("é", 40))
	a1.register()
	a2.conn.Close()
	waitOnline(t, ts, "alpha", 1)

	snap := ts.Snapshot()
	if snap.Started.After(before) || snap.RelayPackets != 0 || snap.RelayBytes != 0 {
		t.Errorf("snapshot = %+v", snap)
	}
	if len(snap.Networks) != 2 || snap.Networks[0].Name != "alpha" || snap.Networks[1].Name != "zeta" {
		t.Fatalf("networks = %+v, want alpha and zeta", snap.Networks)
	}
	alpha, zeta := snap.Networks[0], snap.Networks[1]
	if alpha.Online != 1 || len(alpha.Devices) != 2 || zeta.Online != 1 || len(zeta.Devices) != 1 {
		t.Fatalf("networks = %+v", snap.Networks)
	}
	for _, nw := range snap.Networks {
		if nw.Created.Before(before.Add(-time.Second)) || nw.Created.After(time.Now()) {
			t.Errorf("%s created %s", nw.Name, nw.Created)
		}
	}

	d1, d2 := alpha.Devices[0], alpha.Devices[1]
	if d1.ID != "a1" || d1.IP != a1.ip || d1.Name != "player" || !d1.Online || d1.Public != a1.public() ||
		d1.Connected.IsZero() || d1.LastSeen.IsZero() {
		t.Errorf("online device = %+v", d1)
	}
	if d2.ID != "a2" || d2.IP != "10.77.0.2" || d2.Online || d2.Public != "" || !d2.Connected.IsZero() ||
		d2.Name != strings.Repeat("é", 32) || !utf8.ValidString(d2.Name) || d2.LastSeen.Before(d1.LastSeen) {
		t.Errorf("offline device = %+v", d2)
	}
	zd := zeta.Devices[0]
	if zd.ID != "z1" || zd.IP != z.ip || zd.Name != "Zed" {
		t.Errorf("zeta device = %+v", zd)
	}
	wantLocal := []string{"192.168.1.5:5000"}
	for i := range 7 {
		wantLocal = append(wantLocal, fmt.Sprintf("10.0.1.%d:6000", i+1))
	}
	if !slices.Equal(zd.Local, wantLocal) {
		t.Errorf("local endpoints = %q, want %q", zd.Local, wantLocal)
	}

	// The dashboard gets JSON; offline devices have no connection time.
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var back Snapshot
	if err := json.Unmarshal(b, &back); err != nil || len(back.Networks) != 2 {
		t.Fatalf("snapshot JSON round trip: %v\n%s", err, b)
	}
	if bytes.Count(b, []byte(`"connected"`)) != 2 {
		t.Errorf("want exactly the two online devices to have a connection time:\n%s", b)
	}
}

func TestRemoveDevice(t *testing.T) {
	ts := startServer(t, "")
	a := mustJoin(t, ts, "LAN", authA, "dev-a", "Alice")
	b := mustJoin(t, ts, "lan", authA, "dev-b", "Bob")
	a.register()
	b.register()

	if err := ts.RemoveDevice(" Lan ", "dev-a"); err != nil {
		t.Fatal(err)
	}
	a.closed()
	b.peersUntil("alice removed", func(p []proto.PeerInfo) bool { return len(p) == 1 && p[0].IP == b.ip })
	nw := findNetwork(ts.Snapshot(), "lan")
	if nw.Online != 1 || len(nw.Devices) != 1 || nw.Devices[0].ID != "dev-b" {
		t.Errorf("network after removal = %+v", nw)
	}
	// The old session is dead and nothing is relayed to the old endpoint.
	expectNoAck(t, a.udp, ts.addr, a.session)
	b.sendUDP(peerPacket(proto.TypeData, a.ip, b.ip, "to removed"))

	if err := ts.RemoveDevice("lan", "dev-a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing twice: %v, want ErrNotFound", err)
	}
	if err := ts.RemoveDevice("nope", "dev-b"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown network: %v, want ErrNotFound", err)
	}

	// The freed address is reused, and offline devices can be removed too.
	c := mustJoin(t, ts, "lan", authA, "dev-c", "Carol")
	if c.ip != "10.77.0.1" {
		t.Errorf("new device got %s, want the freed 10.77.0.1", c.ip)
	}
	c.conn.Close()
	waitOnline(t, ts, "lan", 1)
	if err := ts.RemoveDevice("lan", "dev-c"); err != nil {
		t.Fatal(err)
	}
	if nw := findNetwork(ts.Snapshot(), "lan"); len(nw.Devices) != 1 || ts.Snapshot().RelayPackets != 0 {
		t.Errorf("network = %+v, relayed %d", nw, ts.Snapshot().RelayPackets)
	}
}

func TestDeleteNetwork(t *testing.T) {
	ts := startServer(t, "")
	a := mustJoin(t, ts, "LAN", authA, "dev-a", "Alice")
	b := mustJoin(t, ts, "lan", authA, "dev-b", "Bob")
	o := mustJoin(t, ts, "other", authB, "dev-o", "Otto")
	a.register()

	if err := ts.DeleteNetwork("  Lan "); err != nil {
		t.Fatal(err)
	}
	a.closed()
	b.closed()
	snap := ts.Snapshot()
	if len(snap.Networks) != 1 || snap.Networks[0].Name != "other" || snap.Networks[0].Online != 1 {
		t.Errorf("networks after delete = %+v", snap.Networks)
	}
	expectNoAck(t, a.udp, ts.addr, a.session)
	if err := ts.DeleteNetwork("lan"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting twice: %v, want ErrNotFound", err)
	}

	// The next client recreates it with its own password.
	if c := mustJoin(t, ts, "lan", authB, "dev-c", "Carol"); c.ip != "10.77.0.1" {
		t.Errorf("first device in the recreated network got %s", c.ip)
	}
	if msg := join(t, ts, "lan", authA, "dev-a", "Alice").refused(); !strings.Contains(msg, "password") {
		t.Errorf("old password after recreate: %q", msg)
	}
	o.send(proto.Msg{Type: proto.MsgPing})
	for {
		if m, ok := o.next(time.Now().Add(msgTimeout)); !ok {
			t.Fatal("the other network was disconnected")
		} else if m.Type == proto.MsgPong {
			break
		}
	}
}

func TestNetworkFull(t *testing.T) {
	ts := startServer(t, "")
	for i := 1; i <= 254; i++ {
		c := mustJoin(t, ts, "full", authA, fmt.Sprintf("dev-%d", i), "")
		if want := fmt.Sprintf("10.77.0.%d", i); c.ip != want {
			t.Fatalf("device %d got %s, want %s", i, c.ip, want)
		}
		c.conn.Close()
	}
	if msg := join(t, ts, "full", authA, "dev-255", "").refused(); !strings.Contains(msg, "full") {
		t.Errorf("refusal %q doesn't say the network is full", msg)
	}
	if c := mustJoin(t, ts, "full", authA, "dev-254", ""); c.ip != "10.77.0.254" {
		t.Errorf("known device got %s, want 10.77.0.254", c.ip)
	}
}
