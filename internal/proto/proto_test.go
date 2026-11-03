package proto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var (
	keyMu    sync.Mutex
	keyCache = map[[2]string]*Keys{}
)

// keys caches DeriveKeys, which costs ~100ms and 64 MiB per call.
func keys(t *testing.T, network, password string) *Keys {
	t.Helper()
	keyMu.Lock()
	defer keyMu.Unlock()
	id := [2]string{network, password}
	if k := keyCache[id]; k != nil {
		return k
	}
	k, err := DeriveKeys(network, password)
	if err != nil {
		t.Fatal(err)
	}
	keyCache[id] = k
	return k
}

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
		Type: MsgJoin, Version: Version, Network: "lan", Auth: strings.Repeat("ab", 32),
		Device: "dev", Name: "Zain", Local: []string{"192.168.1.2:5000"},
	}
	b, err := json.Marshal(join)
	if err != nil {
		t.Fatal(err)
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
