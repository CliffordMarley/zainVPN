// Package server is the zainVPN coordinator: it admits clients to networks,
// assigns virtual IPs, tells peers how to reach each other, and relays UDP
// between peers that can't connect directly.
package server

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"zainvpn/internal/proto"
)

const (
	joinTimeout  = 10 * time.Second
	idleTimeout  = 60 * time.Second // clients ping every 20s
	writeTimeout = 5 * time.Second
	maxLine      = 64 << 10
	maxLocal     = 8
	maxNameLen   = 32
)

type Server struct {
	log       *log.Logger
	statePath string
	started   time.Time

	mu       sync.RWMutex
	networks map[string]*network
	sessions map[[proto.SessionLen]byte]*member
	byAddr   map[netip.AddrPort]*member // registered UDP endpoint -> member

	udp *net.UDPConn

	relayPackets atomic.Uint64
	relayBytes   atomic.Uint64

	// SharePort is told to clients as the shared-files HTTP port (0: off).
	SharePort int
	// OnNetworkDeleted, if set, is called after DeleteNetwork forgets a network.
	OnNetworkDeleted func(network string)
}

// Member identifies an online device by its control session.
type Member struct {
	Network, Device, Name string
}

// MemberBySession finds the online device with the given hex session, as
// sent in the welcome message. The file service uses it to authenticate.
func (s *Server) MemberBySession(session string) (Member, bool) {
	b, err := hex.DecodeString(session)
	if err != nil || len(b) != proto.SessionLen {
		return Member{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.sessions[[proto.SessionLen]byte(b)]
	if m == nil {
		return Member{}, false
	}
	return Member{Network: m.nw.Name, Device: m.id, Name: m.name}, true
}

type network struct {
	Name     string             `json:"name"`
	Label    string             `json:"label,omitempty"` // human name from the invite code
	AuthHash string             `json:"authHash"`
	Created  time.Time          `json:"created"`
	Devices  map[string]*device `json:"devices"` // by device ID

	online map[netip.Addr]*member
	sendMu sync.Mutex // serializes peer-list broadcasts so none arrive stale
}

type device struct {
	IP       netip.Addr `json:"ip"`
	Name     string     `json:"name"`
	LastSeen time.Time  `json:"lastSeen"`
}

type member struct {
	nw        *network
	id        string
	ip        netip.Addr
	name      string
	local     []string
	session   [proto.SessionLen]byte
	addr      netip.AddrPort // as received on the UDP socket; valid once registered
	connected time.Time

	relayBytes atomic.Uint64

	conn net.Conn
	wmu  sync.Mutex
}

// New loads state from statePath (if it exists) and returns a server.
func New(statePath string, logger *log.Logger) (*Server, error) {
	s := &Server{
		log:       logger,
		statePath: statePath,
		started:   time.Now(),
		networks:  map[string]*network{},
		sessions:  map[[proto.SessionLen]byte]*member{},
		byAddr:    map[netip.AddrPort]*member{},
	}
	if statePath != "" {
		b, err := os.ReadFile(statePath)
		switch {
		case err == nil:
			if err := json.Unmarshal(b, &s.networks); err != nil {
				return nil, err
			}
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
	}
	for _, nw := range s.networks {
		nw.online = map[netip.Addr]*member{}
		if nw.Devices == nil {
			nw.Devices = map[string]*device{}
		}
	}
	return s, nil
}

// Serve runs the coordinator on the given listeners. It returns once ln is
// closed; close udp too to stop the relay.
func (s *Server) Serve(ln net.Listener, udp *net.UDPConn) error {
	s.udp = udp
	go s.serveUDP()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Printf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.handleConn(c)
	}
}

func (s *Server) handleConn(c net.Conn) {
	defer c.Close()
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 4096), maxLine)

	c.SetReadDeadline(time.Now().Add(joinTimeout))
	if !sc.Scan() {
		return
	}
	var join proto.Msg
	if err := json.Unmarshal(sc.Bytes(), &join); err != nil || join.Type != proto.MsgJoin {
		return
	}
	m, refusal := s.join(c, &join)
	if refusal != "" {
		s.log.Printf("refused %s (network %q): %s", c.RemoteAddr(), join.Network, refusal)
		if refusal == errWrongPassword {
			time.Sleep(time.Second) // slow down guessing
		}
		writeMsg(c, nil, &proto.Msg{Type: proto.MsgError, Error: refusal})
		return
	}
	s.log.Printf("%s joined %q as %s (%s)", m.name, m.nw.Name, m.ip, c.RemoteAddr())
	defer s.leave(m)

	if err := s.send(m, &proto.Msg{
		Type: proto.MsgWelcome, IP: m.ip.String(), Session: hex.EncodeToString(m.session[:]), SharePort: s.SharePort,
	}); err != nil {
		return
	}
	s.broadcastPeers(m.nw)

	for {
		c.SetReadDeadline(time.Now().Add(idleTimeout))
		if !sc.Scan() {
			return
		}
		var msg proto.Msg
		if json.Unmarshal(sc.Bytes(), &msg) != nil {
			return
		}
		if msg.Type == proto.MsgPing {
			if s.send(m, &proto.Msg{Type: proto.MsgPong}) != nil {
				return
			}
		}
	}
}

const errWrongPassword = "wrong password for this network"

func (s *Server) join(c net.Conn, j *proto.Msg) (*member, string) {
	key := proto.NormalizeNetwork(j.Network)
	switch {
	case j.Version != proto.Version:
		return nil, "incompatible client version, please update zainVPN"
	case key == "" || len(key) > 64:
		return nil, "invalid network name"
	case len(j.Auth) != proto.AuthLen:
		return nil, "invalid credentials"
	case j.Device == "" || len(j.Device) > 64:
		return nil, "invalid device id"
	}
	name := cleanName(j.Name)
	hash := proto.AuthHash(j.Auth)

	s.mu.Lock()
	defer s.mu.Unlock()
	nw := s.networks[key]
	if nw == nil {
		nw = &network{
			Name: key, AuthHash: hash, Created: time.Now().UTC(),
			Devices: map[string]*device{}, online: map[netip.Addr]*member{},
		}
		if j.Label != "" {
			nw.Label = proto.CleanLabel(j.Label)
		}
		s.networks[key] = nw
		s.log.Printf("created network %q (%s)", nw.Label, key)
	} else if subtle.ConstantTimeCompare([]byte(hash), []byte(nw.AuthHash)) != 1 {
		return nil, errWrongPassword
	}

	d := nw.Devices[j.Device]
	if d == nil {
		ip, ok := nw.freeIP()
		if !ok {
			return nil, "network is full"
		}
		d = &device{IP: ip}
		nw.Devices[j.Device] = d
	}
	d.Name = name
	d.LastSeen = time.Now().UTC()

	if old := nw.online[d.IP]; old != nil {
		s.dropLocked(old)
		old.conn.Close()
	}
	m := &member{
		nw: nw, id: j.Device, ip: d.IP, name: name, local: cleanEndpoints(j.Local),
		conn: c, connected: time.Now().UTC(),
	}
	rand.Read(m.session[:])
	nw.online[m.ip] = m
	s.sessions[m.session] = m
	s.saveLocked()
	return m, ""
}

func (s *Server) leave(m *member) {
	s.mu.Lock()
	if m.nw.online[m.ip] == m {
		s.dropLocked(m)
	}
	if d := m.nw.Devices[m.id]; d != nil {
		d.LastSeen = time.Now().UTC()
	}
	s.saveLocked()
	s.mu.Unlock()
	s.log.Printf("%s left %q", m.name, m.nw.Name)
	s.broadcastPeers(m.nw)
}

// dropLocked removes an online member from all indexes. Caller holds s.mu.
func (s *Server) dropLocked(m *member) {
	if m.nw.online[m.ip] == m {
		delete(m.nw.online, m.ip)
	}
	if s.sessions[m.session] == m {
		delete(s.sessions, m.session)
	}
	if m.addr.IsValid() && s.byAddr[m.addr] == m {
		delete(s.byAddr, m.addr)
	}
}

func (nw *network) freeIP() (netip.Addr, bool) {
	used := map[netip.Addr]bool{}
	for _, d := range nw.Devices {
		used[d.IP] = true
	}
	for ip := proto.Subnet.Addr().Next(); ip != proto.Broadcast; ip = ip.Next() {
		if !used[ip] {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// broadcastPeers sends the network's current member list to every online member.
func (s *Server) broadcastPeers(nw *network) {
	nw.sendMu.Lock()
	defer nw.sendMu.Unlock()

	s.mu.RLock()
	peers := make([]proto.PeerInfo, 0, len(nw.Devices))
	for _, d := range nw.Devices {
		pi := proto.PeerInfo{IP: d.IP.String(), Name: d.Name}
		if m := nw.online[d.IP]; m != nil {
			pi.Online = true
			pi.Local = m.local
			if m.addr.IsValid() {
				pi.Public = unmap(m.addr).String()
			}
		}
		peers = append(peers, pi)
	}
	targets := make([]*member, 0, len(nw.online))
	for _, m := range nw.online {
		targets = append(targets, m)
	}
	s.mu.RUnlock()

	sort.Slice(peers, func(i, j int) bool {
		return netip.MustParseAddr(peers[i].IP).Less(netip.MustParseAddr(peers[j].IP))
	})
	msg := &proto.Msg{Type: proto.MsgPeers, Peers: peers}
	for _, m := range targets {
		if err := s.send(m, msg); err != nil {
			m.conn.Close()
		}
	}
}

func (s *Server) send(m *member, msg *proto.Msg) error {
	return writeMsg(m.conn, &m.wmu, msg)
}

func writeMsg(c net.Conn, mu *sync.Mutex, msg *proto.Msg) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	c.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err = c.Write(b)
	return err
}

func (s *Server) serveUDP() {
	buf := make([]byte, 65535)
	for {
		n, from, err := s.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}
		pkt := buf[:n]
		switch pkt[0] {
		case proto.TypeRegister:
			if n == 1+proto.SessionLen {
				s.register([proto.SessionLen]byte(pkt[1:]), from)
			}
		case proto.TypeData, proto.TypePing, proto.TypePong:
			s.relay(pkt, from)
		}
	}
}

// register records the UDP endpoint a client's packets arrive from. That
// endpoint is the client's public address, which peers use to punch through.
func (s *Server) register(session [proto.SessionLen]byte, from netip.AddrPort) {
	s.mu.Lock()
	m := s.sessions[session]
	if m == nil {
		s.mu.Unlock()
		return
	}
	changed := m.addr != from
	if changed {
		if m.addr.IsValid() && s.byAddr[m.addr] == m {
			delete(s.byAddr, m.addr)
		}
		m.addr = from
		s.byAddr[from] = m
	}
	s.mu.Unlock()

	s.udp.WriteToUDPAddrPort([]byte{proto.TypeRegisterAck}, from)
	if changed {
		// Not on the UDP goroutine: a slow TCP peer must not stall the relay.
		go s.broadcastPeers(m.nw)
	}
}

// relay forwards a peer packet to the member whose virtual IP is in its header.
func (s *Server) relay(pkt []byte, from netip.AddrPort) {
	if len(pkt) < proto.Overhead {
		return
	}
	_, dst, src := proto.ParseHeader(pkt)

	s.mu.RLock()
	var to netip.AddrPort
	sender := s.byAddr[from]
	if sender != nil && sender.ip == src {
		if t := sender.nw.online[dst]; t != nil && t != sender {
			to = t.addr
		}
	}
	s.mu.RUnlock()

	if to.IsValid() {
		s.relayPackets.Add(1)
		s.relayBytes.Add(uint64(len(pkt)))
		sender.relayBytes.Add(uint64(len(pkt)))
		s.udp.WriteToUDPAddrPort(pkt, to)
	}
}

// saveLocked persists networks and devices. Caller holds s.mu.
func (s *Server) saveLocked() {
	if s.statePath == "" {
		return
	}
	b, err := json.MarshalIndent(s.networks, "", "  ")
	if err != nil {
		s.log.Printf("save state: %v", err)
		return
	}
	tmp := s.statePath + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.statePath), 0o755); err == nil {
		err = os.WriteFile(tmp, b, 0o600)
		if err == nil {
			err = os.Rename(tmp, s.statePath)
		}
	}
	if err != nil {
		s.log.Printf("save state: %v", err)
	}
}

// Snapshot is a point-in-time view of the coordinator for the dashboard.
type Snapshot struct {
	Started      time.Time     `json:"started"`
	RelayPackets uint64        `json:"relayPackets"`
	RelayBytes   uint64        `json:"relayBytes"`
	Networks     []NetworkInfo `json:"networks"`
}

type NetworkInfo struct {
	Name    string       `json:"name"`
	Label   string       `json:"label,omitempty"`
	Created time.Time    `json:"created"`
	Online  int          `json:"online"`
	Devices []DeviceInfo `json:"devices"`
}

type DeviceInfo struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	IP         string    `json:"ip"`
	Online     bool      `json:"online"`
	Public     string    `json:"public,omitempty"`
	Local      []string  `json:"local,omitempty"`
	Connected  time.Time `json:"connected,omitzero"`
	LastSeen   time.Time `json:"lastSeen"`
	RelayBytes uint64    `json:"relayBytes"`
}

func (s *Server) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{
		Started:      s.started,
		RelayPackets: s.relayPackets.Load(),
		RelayBytes:   s.relayBytes.Load(),
		Networks:     make([]NetworkInfo, 0, len(s.networks)),
	}
	for _, nw := range s.networks {
		ni := NetworkInfo{Name: nw.Name, Label: nw.Label, Created: nw.Created, Online: len(nw.online)}
		for id, d := range nw.Devices {
			di := DeviceInfo{ID: id, Name: d.Name, IP: d.IP.String(), LastSeen: d.LastSeen}
			if m := nw.online[d.IP]; m != nil && m.id == id {
				di.Online = true
				di.Local = m.local
				di.Connected = m.connected
				di.RelayBytes = m.relayBytes.Load()
				if m.addr.IsValid() {
					di.Public = unmap(m.addr).String()
				}
			}
			ni.Devices = append(ni.Devices, di)
		}
		sort.Slice(ni.Devices, func(i, j int) bool {
			return netip.MustParseAddr(ni.Devices[i].IP).Less(netip.MustParseAddr(ni.Devices[j].IP))
		})
		snap.Networks = append(snap.Networks, ni)
	}
	sort.Slice(snap.Networks, func(i, j int) bool { return snap.Networks[i].Name < snap.Networks[j].Name })
	return snap
}

var ErrNotFound = errors.New("not found")

// DeleteNetwork disconnects everyone in a network and forgets it, so the next
// client to join recreates it with whatever password that client uses.
func (s *Server) DeleteNetwork(name string) error {
	s.mu.Lock()
	nw := s.networks[proto.NormalizeNetwork(name)]
	if nw == nil {
		s.mu.Unlock()
		return ErrNotFound
	}
	delete(s.networks, nw.Name)
	var conns []net.Conn
	for _, m := range nw.online {
		s.dropLocked(m)
		conns = append(conns, m.conn)
	}
	s.saveLocked()
	s.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	s.log.Printf("deleted network %q", nw.Name)
	if s.OnNetworkDeleted != nil {
		s.OnNetworkDeleted(nw.Name)
	}
	return nil
}

// RemoveDevice disconnects a device and frees its IP. If the device still has
// the password it can rejoin, and then gets the lowest free IP (often its old one).
func (s *Server) RemoveDevice(networkName, deviceID string) error {
	s.mu.Lock()
	nw := s.networks[proto.NormalizeNetwork(networkName)]
	if nw == nil || nw.Devices[deviceID] == nil {
		s.mu.Unlock()
		return ErrNotFound
	}
	d := nw.Devices[deviceID]
	delete(nw.Devices, deviceID)
	var conn net.Conn
	if m := nw.online[d.IP]; m != nil && m.id == deviceID {
		s.dropLocked(m)
		conn = m.conn
	}
	s.saveLocked()
	s.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	s.broadcastPeers(nw)
	s.log.Printf("removed device %s (%s) from %q", d.Name, d.IP, nw.Name)
	return nil
}

func cleanName(n string) string {
	n = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(n))
	for utf8.RuneCountInString(n) > maxNameLen {
		_, size := utf8.DecodeLastRuneInString(n)
		n = n[:len(n)-size]
	}
	if n == "" {
		n = "player"
	}
	return n
}

func cleanEndpoints(eps []string) []string {
	var out []string
	for _, e := range eps {
		ap, err := netip.ParseAddrPort(e)
		if err != nil || !ap.Addr().Is4() || ap.Port() == 0 {
			continue
		}
		out = append(out, ap.String())
		if len(out) == maxLocal {
			break
		}
	}
	return out
}

func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
