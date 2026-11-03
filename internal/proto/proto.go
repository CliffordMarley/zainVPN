// Package proto defines zainVPN's wire formats: the encrypted UDP packets
// peers exchange (directly or through the coordinator's relay) and the JSON
// control messages clients exchange with the coordinator over TCP.
package proto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Version is bumped when the wire format changes incompatibly.
const Version = 1

// DefaultPort is the coordinator's port for both TCP (control) and UDP (relay).
const DefaultPort = 29814

// UDP packet types.
const (
	TypeData        byte = 0x01 // an IPv4 packet for the peer's virtual adapter
	TypePing        byte = 0x02 // path probe; payload is an 8-byte timestamp
	TypePong        byte = 0x03 // probe reply; echoes the ping payload
	TypeRegister    byte = 0x10 // client -> coordinator: [type][session]
	TypeRegisterAck byte = 0x11 // coordinator -> client: [type]
)

// Peer packets are [type:1][dst:4][src:4][nonce:24][ciphertext+tag].
// dst and src are virtual IPv4 addresses. They stay in the clear so the relay
// can forward without knowing the key, and are authenticated as additional data.
const (
	HeaderLen  = 9
	NonceLen   = chacha20poly1305.NonceSizeX
	Overhead   = HeaderLen + NonceLen + chacha20poly1305.Overhead
	SessionLen = 16
	AuthLen    = 64 // hex characters in Keys.Auth
)

// MTU of the virtual adapter. 1380 + Overhead + UDP/IP headers stays under a
// typical 1500-byte internet path, with room for PPPoE and similar.
const MTU = 1380

// Every network uses the same range; the coordinator keeps networks isolated.
var (
	Subnet           = netip.MustParsePrefix("10.77.0.0/24")
	Broadcast        = netip.MustParseAddr("10.77.0.255")
	LimitedBroadcast = netip.MustParseAddr("255.255.255.255")
)

var ErrBadPacket = errors.New("bad packet")

// Keys are derived from a network's name and password.
type Keys struct {
	aead cipher.AEAD
	// Auth proves knowledge of the password to the coordinator. It is derived
	// separately from the data key, so the coordinator can't read traffic.
	Auth string
}

// NormalizeNetwork makes network names case- and whitespace-insensitive.
func NormalizeNetwork(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// DeriveKeys runs Argon2id over the password (salted with the network name),
// which takes ~100ms and 64 MiB, so it should be called once per connection.
func DeriveKeys(network, password string) (*Keys, error) {
	salt := []byte("zainvpn/v1/" + NormalizeNetwork(network))
	m := argon2.IDKey([]byte(password), salt, 2, 64*1024, 4, 64)
	aead, err := chacha20poly1305.NewX(m[:32])
	if err != nil {
		return nil, err
	}
	return &Keys{aead: aead, Auth: hex.EncodeToString(m[32:])}, nil
}

// AuthHash is what the coordinator stores to check a network's password.
func AuthHash(auth string) string {
	h := sha256.Sum256([]byte(auth))
	return hex.EncodeToString(h[:])
}

// Seal builds an encrypted peer packet.
func (k *Keys) Seal(typ byte, dst, src netip.Addr, payload []byte) []byte {
	var hdr [HeaderLen]byte
	hdr[0] = typ
	d, s := dst.As4(), src.As4()
	copy(hdr[1:5], d[:])
	copy(hdr[5:9], s[:])

	out := make([]byte, HeaderLen+NonceLen, Overhead+len(payload))
	copy(out, hdr[:])
	nonce := out[HeaderLen:]
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return k.aead.Seal(out, nonce, payload, hdr[:])
}

// Open authenticates and decrypts a peer packet. The returned payload aliases
// pkt, so it is only valid until pkt is reused.
func (k *Keys) Open(pkt []byte) (typ byte, dst, src netip.Addr, payload []byte, err error) {
	if len(pkt) < Overhead {
		return 0, dst, src, nil, ErrBadPacket
	}
	typ, dst, src = ParseHeader(pkt)
	ct := pkt[HeaderLen+NonceLen:]
	payload, err = k.aead.Open(ct[:0], pkt[HeaderLen:HeaderLen+NonceLen], ct, pkt[:HeaderLen])
	return typ, dst, src, payload, err
}

// ParseHeader reads the cleartext header of a peer packet of at least
// HeaderLen bytes. The relay uses it to forward without the key.
func ParseHeader(pkt []byte) (typ byte, dst, src netip.Addr) {
	return pkt[0], netip.AddrFrom4([4]byte(pkt[1:5])), netip.AddrFrom4([4]byte(pkt[5:9]))
}

// Control message types (JSON, one object per line, over TCP).
const (
	MsgJoin    = "join"    // client -> server, first message
	MsgWelcome = "welcome" // server -> client, join accepted
	MsgError   = "error"   // server -> client, join refused; connection closes
	MsgPeers   = "peers"   // server -> client, full member list on any change
	MsgPing    = "ping"    // client -> server keepalive
	MsgPong    = "pong"    // server -> client keepalive reply
)

// Msg is a control message. Only the fields relevant to Type are set.
type Msg struct {
	Type string `json:"type"`

	// join
	Version int      `json:"version,omitempty"`
	Network string   `json:"network,omitempty"`
	Auth    string   `json:"auth,omitempty"`
	Device  string   `json:"device,omitempty"`
	Name    string   `json:"name,omitempty"`
	Local   []string `json:"local,omitempty"` // client's UDP endpoints on its own LAN

	// welcome
	IP      string `json:"ip,omitempty"`
	Session string `json:"session,omitempty"` // hex; proves identity in TypeRegister

	// peers
	Peers []PeerInfo `json:"peers,omitempty"`

	// error
	Error string `json:"error,omitempty"`
}

// PeerInfo describes one member of the network, including the receiver itself.
type PeerInfo struct {
	IP     string   `json:"ip"`
	Name   string   `json:"name"`
	Online bool     `json:"online"`
	Public string   `json:"public,omitempty"` // UDP endpoint as seen by the coordinator
	Local  []string `json:"local,omitempty"`
}
