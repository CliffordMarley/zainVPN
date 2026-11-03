package proto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
)

var (
	keyMu    sync.Mutex
	keyCache = map[any]*Keys{} // by [2]string{network, password} or Invite
)

// cachedKeys caches key derivation, which costs ~100ms and 64 MiB per call.
func cachedKeys(t *testing.T, id any, derive func() (*Keys, error)) *Keys {
	t.Helper()
	keyMu.Lock()
	defer keyMu.Unlock()
	if k := keyCache[id]; k != nil {
		return k
	}
	k, err := derive()
	if err != nil {
		t.Fatal(err)
	}
	keyCache[id] = k
	return k
}

func keys(t *testing.T, network, password string) *Keys {
	t.Helper()
	return cachedKeys(t, [2]string{network, password}, func() (*Keys, error) { return DeriveKeys(network, password) })
}

func inviteKeys(t *testing.T, inv Invite) *Keys {
	t.Helper()
	return cachedKeys(t, inv, inv.Keys)
}

// mkInvite builds an invite with a fixed random part (11 characters), so
// tests that depend on the check character are deterministic.
func mkInvite(label, random string) Invite {
	return Invite{Label: label, Secret: random + string(inviteCheck(label, []byte(random)))}
}

var inviteRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$`)

var (
	ipA = netip.MustParseAddr("10.77.0.1")
	ipB = netip.MustParseAddr("10.77.0.2")
	ipC = netip.MustParseAddr("10.77.0.3")
)

func TestNormalizeNetwork(t *testing.T) {
	for in, want := range map[string]string{
		"lan":                "lan",
		"LAN":                "lan",
		"  Blur Night \t\n":  "blur night",
		"MiXeD-Case_42":      "mixed-case_42",
		"":                   "",
		" \t ":               "",
		"ÄÖÜ":                "äöü",
		"inner  spaces kept": "inner  spaces kept",
	} {
		if got := NormalizeNetwork(in); got != want {
			t.Errorf("NormalizeNetwork(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConstants(t *testing.T) {
	if Overhead != 9+24+16 {
		t.Errorf("Overhead = %d, want 49", Overhead)
	}
	if MTU+Overhead+28 > 1500-8 {
		t.Errorf("MTU %d + overhead doesn't fit a 1492-byte path", MTU)
	}
	if !Subnet.Contains(Broadcast) || Subnet.Contains(Broadcast.Next()) {
		t.Errorf("Broadcast %s is not the last address of %s", Broadcast, Subnet)
	}
	if !LimitedBroadcast.Is4() || Subnet.Bits() != 24 {
		t.Errorf("unexpected LimitedBroadcast %s / Subnet %s", LimitedBroadcast, Subnet)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := keys(t, "lan", "hunter2")
	for _, n := range []int{0, 1, 20, 512, MTU} {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i*7 + 3)
		}
		orig := bytes.Clone(payload)
		for _, typ := range []byte{TypeData, TypePing, TypePong} {
			pkt := k.Seal(typ, ipB, ipA, payload)
			if !bytes.Equal(payload, orig) {
				t.Fatal("Seal modified its payload")
			}
			if len(pkt) != Overhead+n {
				t.Fatalf("len(Seal) = %d, want %d", len(pkt), Overhead+n)
			}
			if htyp, hdst, hsrc := ParseHeader(pkt); htyp != typ || hdst != ipB || hsrc != ipA {
				t.Fatalf("ParseHeader = %#x %s %s, want %#x %s %s", htyp, hdst, hsrc, typ, ipB, ipA)
			}
			if n >= 16 && bytes.Contains(pkt, payload) {
				t.Fatal("payload is visible in the sealed packet")
			}
			gtyp, dst, src, got, err := k.Open(bytes.Clone(pkt))
			if err != nil {
				t.Fatalf("Open(type %#x, %d bytes): %v", typ, n, err)
			}
			if gtyp != typ || dst != ipB || src != ipA || !bytes.Equal(got, payload) {
				t.Fatalf("Open = %#x %s %s %d bytes, want %#x %s %s %d bytes", gtyp, dst, src, len(got), typ, ipB, ipA, n)
			}
		}
	}

	// Every packet gets a fresh random nonce.
	p1 := k.Seal(TypeData, ipB, ipA, []byte("same"))
	p2 := k.Seal(TypeData, ipB, ipA, []byte("same"))
	if bytes.Equal(p1[HeaderLen:HeaderLen+NonceLen], p2[HeaderLen:HeaderLen+NonceLen]) || bytes.Equal(p1, p2) {
		t.Error("two Seal calls produced the same nonce")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	k := keys(t, "lan", "hunter2")
	pkt := k.Seal(TypeData, ipB, ipA, []byte("hello, blur"))
	region := func(i int) string {
		switch {
		case i < HeaderLen:
			return "header"
		case i < HeaderLen+NonceLen:
			return "nonce"
		}
		return "ciphertext"
	}
	for i := range pkt {
		for _, bit := range []byte{0x01, 0x80} {
			bad := bytes.Clone(pkt)
			bad[i] ^= bit
			if _, _, _, _, err := k.Open(bad); err == nil {
				t.Errorf("Open accepted a packet with %s byte %d flipped (^%#x)", region(i), i, bit)
			}
		}
	}

	// What a malicious relay or peer might try.
	for name, mutate := range map[string]func([]byte) []byte{
		"src rewritten": func(p []byte) []byte { copy(p[5:9], ipC.AsSlice()); return p },
		"dst rewritten": func(p []byte) []byte { copy(p[1:5], ipC.AsSlice()); return p },
		"type changed":  func(p []byte) []byte { p[0] = TypePing; return p },
		"nonce zeroed":  func(p []byte) []byte { clear(p[HeaderLen : HeaderLen+NonceLen]); return p },
		"tag truncated": func(p []byte) []byte { return p[:len(p)-1] },
		"byte appended": func(p []byte) []byte { return append(p, 0) },
		"byte removed":  func(p []byte) []byte { return append(p[:HeaderLen+NonceLen], p[HeaderLen+NonceLen+1:]...) },
	} {
		if _, _, _, _, err := k.Open(mutate(bytes.Clone(pkt))); err == nil {
			t.Errorf("Open accepted a packet with %s", name)
		}
	}
}

func TestOpenRejectsShortPackets(t *testing.T) {
	k := keys(t, "lan", "hunter2")
	pkt := k.Seal(TypeData, ipB, ipA, nil)
	if len(pkt) != Overhead {
		t.Fatalf("empty payload sealed to %d bytes, want %d", len(pkt), Overhead)
	}
	for n := range Overhead {
		if _, _, _, _, err := k.Open(bytes.Clone(pkt[:n])); !errors.Is(err, ErrBadPacket) {
			t.Errorf("Open(%d bytes) = %v, want ErrBadPacket", n, err)
		}
		if _, _, _, _, err := k.Open(make([]byte, n)); !errors.Is(err, ErrBadPacket) {
			t.Errorf("Open(%d zero bytes) = %v, want ErrBadPacket", n, err)
		}
	}
	if _, _, _, _, err := k.Open(make([]byte, Overhead)); err == nil {
		t.Error("Open accepted an all-zero packet")
	}
}

func TestWrongPassword(t *testing.T) {
	k := keys(t, "lan", "hunter2")
	wrong := keys(t, "lan", "hunter3")
	if _, _, _, _, err := wrong.Open(k.Seal(TypeData, ipB, ipA, []byte("secret"))); err == nil {
		t.Error("a different password opened the packet")
	}
	if k.Auth == wrong.Auth || AuthHash(k.Auth) == AuthHash(wrong.Auth) {
		t.Error("different passwords produced the same auth token")
	}
}

func TestKeysPerNetwork(t *testing.T) {
	k := keys(t, "lan", "hunter2")
	other := keys(t, "other lan", "hunter2")
	if _, _, _, _, err := other.Open(k.Seal(TypeData, ipB, ipA, []byte("secret"))); err == nil {
		t.Error("the same password in another network opened the packet")
	}
	if k.Auth == other.Auth {
		t.Error("the same password in another network produced the same auth token")
	}

	// Network names are normalized before salting, and derivation is deterministic.
	same := keys(t, "  LAN ", "hunter2")
	if same.Auth != k.Auth {
		t.Error(`"  LAN " and "lan" derived different auth tokens`)
	}
	_, _, _, got, err := same.Open(k.Seal(TypeData, ipB, ipA, []byte("secret")))
	if err != nil || string(got) != "secret" {
		t.Errorf(`"  LAN " couldn't open a "lan" packet: %v`, err)
	}
}

func TestAuth(t *testing.T) {
	k := keys(t, "lan", "hunter2")
	if len(k.Auth) != AuthLen {
		t.Fatalf("len(Auth) = %d, want %d", len(k.Auth), AuthLen)
	}
	if _, err := hex.DecodeString(k.Auth); err != nil {
		t.Errorf("Auth %q is not hex: %v", k.Auth, err)
	}
	h := AuthHash(k.Auth)
	if len(h) != 64 || h != AuthHash(k.Auth) || h == k.Auth || strings.Contains(h, k.Auth) {
		t.Errorf("AuthHash(%q) = %q", k.Auth, h)
	}
}

func TestMsgJSON(t *testing.T) {
	join := Msg{
		Type: MsgJoin, Version: Version, Network: strings.Repeat("0f", 16), Label: "blur", Auth: strings.Repeat("ab", 32),
		Device: "dev", Name: "Zain", Local: []string{"192.168.1.2:5000"},
	}
	b, err := json.Marshal(join)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"label":"blur"`)) {
		t.Errorf("join = %s, want the label on the wire", b)
	}
	var back Msg
	if err := json.Unmarshal(b, &back); err != nil || !reflect.DeepEqual(back, join) {
		t.Errorf("join round trip: %+v, %v", back, err)
	}

	// Unused fields stay off the wire.
	b, _ = json.Marshal(Msg{Type: MsgPing})
	if string(b) != `{"type":"ping"}` {
		t.Errorf("ping = %s", b)
	}
	b, _ = json.Marshal(Msg{Type: MsgPeers, Peers: []PeerInfo{{IP: "10.77.0.1", Name: "a"}}})
	if want := `{"type":"peers","peers":[{"ip":"10.77.0.1","name":"a","online":false}]}`; string(b) != want {
		t.Errorf("peers = %s, want %s", b, want)
	}
}

var labelRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func TestCleanLabel(t *testing.T) {
	cases := map[string]string{
		"blur":                            "blur",
		"Blur Night!":                     "blur-night",
		"  Blur   Night  ":                "blur-night",
		"LAN_party - 2":                   "lan-party-2",
		"--blur--":                        "blur",
		"a!b?c":                           "abc",
		"Ünïcode":                         "ncode",
		"<b>Blur</b>":                     "bblurb",
		"":                                "lan",
		"   ":                             "lan",
		"!!!":                             "lan",
		"- _ -":                           "lan",
		strings.Repeat("ab", 10):          strings.Repeat("ab", 10),
		strings.Repeat("a", 30):           strings.Repeat("a", maxLabelLen),
		strings.Repeat("a", 19) + " club": strings.Repeat("a", 19), // cut at the dash, which is then trimmed
	}
	for in, want := range cases {
		got := CleanLabel(in)
		if got != want {
			t.Errorf("CleanLabel(%q) = %q, want %q", in, got, want)
		}
		// Every result is a valid label, and cleaning it again changes nothing.
		if !labelRe.MatchString(got) || len(got) > maxLabelLen || CleanLabel(got) != got {
			t.Errorf("CleanLabel(%q) = %q is not a clean label", in, got)
		}
	}
}

func TestNewInvite(t *testing.T) {
	seen := map[string]bool{}
	used := map[rune]bool{}
	for _, label := range []string{"blur", "Blur Night!", "", "lan-party-2", strings.Repeat("x", 40)} {
		for range 50 {
			inv := NewInvite(label)
			if inv.Label != CleanLabel(label) || len(inv.Secret) != inviteLen {
				t.Fatalf("NewInvite(%q) = %+v", label, inv)
			}
			code := inv.String()
			if !inviteRe.MatchString(code) || !strings.HasPrefix(code, inv.Label+"-") {
				t.Fatalf("NewInvite(%q).String() = %q", label, code)
			}
			if seen[inv.Secret] {
				t.Fatalf("NewInvite repeated the secret %q", inv.Secret)
			}
			seen[inv.Secret] = true
			for _, r := range inv.Secret[:inviteRandom] {
				used[r] = true
			}
			if got, err := ParseInvite(code); err != nil || got != inv {
				t.Fatalf("ParseInvite(%q) = %+v, %v, want %+v", code, got, err, inv)
			}
		}
	}
	if len(used) != len(inviteAlphabet) {
		t.Errorf("random parts only used %d of the %d alphabet characters", len(used), len(inviteAlphabet))
	}
	if inv := NewInvite("  "); inv.Label != "lan" || !strings.HasPrefix(inv.String(), "lan-") {
		t.Errorf("NewInvite with a blank name = %q, want a lan-... code", inv)
	}
}

func TestParseInviteLenient(t *testing.T) {
	// The random part has a 0 and a 1 to misread; the label has an "l" that must stay.
	inv := mkInvite("blur", "R0VB1XPQ8MN")
	code, sec := inv.String(), inv.Secret
	party := mkInvite("lan-party-2", "0123456789A")
	ps := party.Secret
	for in, want := range map[string]Invite{
		code:                  inv,
		strings.ToLower(code): inv,
		strings.ToUpper(code): inv,
		"  " + code + " \r\n": inv,
		code + " ":            inv, // non-breaking space from a chat app
		"blur " + sec[0:4] + " " + sec[4:8] + " " + sec[8:]:       inv,
		"blur - " + sec[0:4] + " - " + sec[4:8] + " - " + sec[8:]: inv,
		"blur-" + sec:                 inv,
		"blur" + sec:                  inv,
		"blur" + strings.ToLower(sec): inv,
		"blur--" + sec[0:2] + "-" + sec[2:] + "-":               inv,
		strings.ReplaceAll(code, "0", "O"):                      inv,
		strings.ReplaceAll(code, "0", "o"):                      inv,
		strings.ReplaceAll(code, "1", "I"):                      inv,
		strings.ReplaceAll(code, "1", "i"):                      inv,
		strings.ReplaceAll(code, "1", "L"):                      inv,
		strings.ReplaceAll(code, "1", "l"):                      inv,
		party.String():                                          party,
		strings.ToUpper(party.String()):                         party,
		"lan-party-2 " + ps[0:4] + " " + ps[4:8] + " " + ps[8:]: party,
		"lan-party-2" + strings.ToLower(ps):                     party,
	} {
		if got, err := ParseInvite(in); err != nil || got != want {
			t.Errorf("ParseInvite(%q) = %+v, %v, want %+v", in, got, err, want)
		}
	}
}

func TestParseInviteRejects(t *testing.T) {
	inv := mkInvite("blur", "R0VB1XPQ8MN")
	code, sec := inv.String(), inv.Secret
	for _, in := range []string{
		"", "   ", "blur", "blur-", "hunter2",
		sec, "-" + sec, " - " + sec, // no label
		"blur-" + sec[:10], // too short
		code + "!",
		"blur-" + sec[:11] + "U", // not in the alphabet
		"blür-" + sec,
		"blur_night-" + sec,
		"-blur-" + sec,
		"blur--night-" + sec,
		strings.Repeat("a", maxLabelLen+1) + "-" + sec,
		"https://example.com/" + code,
	} {
		if got, err := ParseInvite(in); !errors.Is(err, ErrBadInvite) {
			t.Errorf("ParseInvite(%q) = %+v, %v, want ErrBadInvite", in, got, err)
		}
	}
}

func TestInviteTypos(t *testing.T) {
	inv := mkInvite("blur", "R0VB1XPQ8MN")
	sec := inv.Secret
	// caught reports whether ParseInvite rejects the code as a typo.
	caught := func(label, secret string) bool {
		t.Helper()
		code := label + "-" + secret
		got, err := ParseInvite(code)
		if err == nil {
			if got == inv {
				t.Fatalf("ParseInvite(%q) returned the original invite", code)
			}
			return false
		}
		if errors.Is(err, ErrBadInvite) || !strings.Contains(err.Error(), "typo") {
			t.Fatalf("ParseInvite(%q) = %v, want the typo error", code, err)
		}
		return true
	}
	replace := func(s string, i int, c byte) string { return s[:i] + string(c) + s[i+1:] }

	// Any change to the check character is caught.
	for _, c := range []byte(inviteAlphabet) {
		if c != sec[inviteRandom] && !caught(inv.Label, replace(sec, inviteRandom, c)) {
			t.Errorf("check character changed to %c wasn't caught", c)
		}
	}

	// A change to one random character is caught about 31 times in 32.
	total := 0
	for i := range inviteRandom {
		n := 0
		for _, c := range []byte(inviteAlphabet) {
			if c != sec[i] && caught(inv.Label, replace(sec, i, c)) {
				n++
			}
		}
		if n < 24 {
			t.Errorf("only %d of 31 changes at position %d were caught", n, i)
		}
		total += n
	}
	if all := inviteRandom * (len(inviteAlphabet) - 1); total < all*9/10 {
		t.Errorf("only %d of %d single-character changes were caught", total, all)
	}

	// So are swapped neighbours, and typos in the label.
	swaps := 0
	for i := range inviteRandom {
		b := []byte(sec)
		b[i], b[i+1] = b[i+1], b[i]
		if caught(inv.Label, string(b)) {
			swaps++
		}
	}
	if swaps < 9 {
		t.Errorf("only %d of %d swapped neighbours were caught", swaps, inviteRandom)
	}
	labels, n := 0, 0
	for i := range len(inv.Label) {
		for c := byte('a'); c <= 'z'; c++ {
			if c != inv.Label[i] {
				labels++
				if caught(replace(inv.Label, i, c), sec) {
					n++
				}
			}
		}
	}
	if n < labels*9/10 {
		t.Errorf("only %d of %d label typos were caught", n, labels)
	}
}

func TestInviteKeys(t *testing.T) {
	inv := mkInvite("blur", "R0VB1XPQ8MN")
	k := inviteKeys(t, inv)
	if len(k.Auth) != AuthLen || len(k.NetworkID) != 32 {
		t.Fatalf("Auth %q, NetworkID %q", k.Auth, k.NetworkID)
	}
	for _, s := range []string{k.Auth, k.NetworkID} {
		if _, err := hex.DecodeString(s); err != nil || strings.Contains(s, inv.Label) || strings.Contains(strings.ToUpper(s), inv.Secret) {
			t.Errorf("derived value %q: %v", s, err)
		}
	}

	// Seal and Open work with invite keys.
	pkt := k.Seal(TypeData, ipB, ipA, []byte("hello, blur"))
	if typ, dst, src, got, err := k.Open(bytes.Clone(pkt)); err != nil || typ != TypeData || dst != ipB || src != ipA || string(got) != "hello, blur" {
		t.Fatalf("Open = %#x %s %s %q, %v", typ, dst, src, got, err)
	}

	// The same invite, however it was typed, always derives the same keys.
	parsed, err := ParseInvite(strings.ToLower(strings.ReplaceAll(inv.String(), "-", " ")))
	if err != nil {
		t.Fatal(err)
	}
	again, err := parsed.Keys() // not cached
	if err != nil {
		t.Fatal(err)
	}
	if again.NetworkID != k.NetworkID || again.Auth != k.Auth {
		t.Errorf("second derivation: %s/%s, want %s/%s", again.NetworkID, again.Auth, k.NetworkID, k.Auth)
	}
	if _, _, _, got, err := again.Open(k.Seal(TypeData, ipB, ipA, []byte("same"))); err != nil || string(got) != "same" {
		t.Errorf("the same invite couldn't open its own packet: %v", err)
	}

	// Any other invite is another network with another key, including the
	// same random part under another label, and legacy password keys.
	others := map[string]*Keys{
		"another secret":           inviteKeys(t, NewInvite(inv.Label)),
		"one character changed":    inviteKeys(t, mkInvite(inv.Label, "R0VB1XPQ8MP")),
		"same secret, other label": inviteKeys(t, Invite{Label: "blur2", Secret: inv.Secret}),
		"legacy password keys":     keys(t, inv.Label, inv.Secret),
	}
	for name, o := range others {
		if o.NetworkID == k.NetworkID || o.Auth == k.Auth || AuthHash(o.Auth) == AuthHash(k.Auth) {
			t.Errorf("%s: same network ID or auth token", name)
		}
		if _, _, _, _, err := o.Open(k.Seal(TypeData, ipB, ipA, []byte("secret"))); err == nil {
			t.Errorf("%s: opened the invite's packet", name)
		}
		if _, _, _, _, err := k.Open(o.Seal(TypeData, ipB, ipA, []byte("secret"))); err == nil {
			t.Errorf("%s: its packet was opened with the invite's key", name)
		}
	}
}
