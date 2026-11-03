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
	"slices"
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

// Keys are derived from an invite code (or a network name and password).
type Keys struct {
	aead cipher.AEAD
	// Auth proves knowledge of the secret to the coordinator. It is derived
	// separately from the data key, so the coordinator can't read traffic.
	Auth string
	// NetworkID is what the coordinator knows the network by.
	NetworkID string
}

// Invite codes look like "blur-7K3M-9X2Q-8W4T": a label the creator chose,
// then 11 random Crockford base32 characters and a check character. The
// random part is the secret; only values derived from it leave the client.
type Invite struct {
	Label  string // lowercase letters, digits and dashes
	Secret string // 12 uppercase characters, no dashes
}

const (
	inviteAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	inviteRandom   = 11
	inviteLen      = inviteRandom + 1
	maxLabelLen    = 20
)

var ErrBadInvite = errors.New("that doesn't look like a zainVPN invite code (example: blur-7K3M-9X2Q-8W4T)")

// NewInvite creates a fresh invite code for a new network called label.
func NewInvite(label string) Invite {
	l := CleanLabel(label)
	var b [inviteRandom]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	s := make([]byte, 0, inviteLen)
	for _, x := range b {
		s = append(s, inviteAlphabet[x&31]) // 256 is a multiple of 32: unbiased
	}
	return Invite{Label: l, Secret: string(append(s, inviteCheck(l, s)))}
}

// CleanLabel turns a user-typed network name into a label: lowercase,
// spaces become dashes, other characters are dropped.
func CleanLabel(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case (r == ' ' || r == '-' || r == '_') && b.Len() > 0 && !dash:
			b.WriteByte('-')
			dash = true
		}
		if b.Len() >= maxLabelLen {
			break
		}
	}
	l := strings.Trim(b.String(), "-")
	if l == "" {
		l = "lan"
	}
	return l
}

// ParseInvite accepts a code in any case, with or without the dashes in
// the random part, and with common Crockford misreadings (O for 0, I/L for 1).
func ParseInvite(code string) (Invite, error) {
	code = strings.Join(strings.Fields(code), "")
	var secret []byte
	i := len(code)
	for i > 0 && len(secret) < inviteLen {
		i--
		c := code[i]
		if c == '-' {
			continue
		}
		switch c = upper(c); c {
		case 'O':
			c = '0'
		case 'I', 'L':
			c = '1'
		}
		if strings.IndexByte(inviteAlphabet, c) < 0 {
			return Invite{}, ErrBadInvite
		}
		secret = append(secret, c)
	}
	label := strings.TrimRight(code[:i], "-")
	if len(secret) != inviteLen || label == "" || CleanLabel(label) != strings.ToLower(label) {
		return Invite{}, ErrBadInvite
	}
	slices.Reverse(secret)
	inv := Invite{Label: strings.ToLower(label), Secret: string(secret)}
	if inviteCheck(inv.Label, secret[:inviteRandom]) != secret[inviteRandom] {
		return Invite{}, errors.New("that invite code has a typo; check it and try again")
	}
	return inv, nil
}

func upper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 'a' + 'A'
	}
	return c
}

// inviteCheck catches 31 of 32 typos in the label or random part, so a
// mistyped code fails here instead of creating an empty network.
func inviteCheck(label string, random []byte) byte {
	h := sha256.Sum256([]byte(label + ":" + string(random)))
	return inviteAlphabet[h[0]&31]
}

// String formats the code for sharing: label-XXXX-XXXX-XXXX.
func (inv Invite) String() string {
	s := inv.Secret
	return inv.Label + "-" + s[0:4] + "-" + s[4:8] + "-" + s[8:12]
}

// Keys derives the network's keys. Like DeriveKeys it costs ~100ms and 64 MiB.
func (inv Invite) Keys() (*Keys, error) {
	salt := []byte("zainvpn/v2/" + inv.Label)
	m := argon2.IDKey([]byte(inv.Secret), salt, 2, 64*1024, 4, 80)
	aead, err := chacha20poly1305.NewX(m[:32])
	if err != nil {
		return nil, err
	}
	return &Keys{aead: aead, Auth: hex.EncodeToString(m[32:64]), NetworkID: hex.EncodeToString(m[64:80])}, nil
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
	return &Keys{aead: aead, Auth: hex.EncodeToString(m[32:]), NetworkID: NormalizeNetwork(network)}, nil
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
	Network string   `json:"network,omitempty"` // Keys.NetworkID
	Label   string   `json:"label,omitempty"`   // the invite's label, shown on the dashboard
	Auth    string   `json:"auth,omitempty"`
	Device  string   `json:"device,omitempty"`
	Name    string   `json:"name,omitempty"`
	Local   []string `json:"local,omitempty"` // client's UDP endpoints on its own LAN

	// welcome
	IP        string `json:"ip,omitempty"`
	Session   string `json:"session,omitempty"`   // hex; proves identity in TypeRegister and to the file service
	SharePort int    `json:"sharePort,omitempty"` // HTTP port of the coordinator's shared files; 0 if off

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
