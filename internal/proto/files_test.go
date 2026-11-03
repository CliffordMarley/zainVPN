package proto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testKeys(t *testing.T) *Keys {
	t.Helper()
	k, err := NewInvite("files").Keys()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestFileRoundTrip(t *testing.T) {
	k := testKeys(t)
	for _, n := range []int{0, 1, fileChunk - 1, fileChunk, fileChunk + 1, 3*fileChunk + 17} {
		pt := make([]byte, n)
		rand.Read(pt)
		var ct, out bytes.Buffer
		if err := k.SealFile(&ct, bytes.NewReader(pt)); err != nil {
			t.Fatal(err)
		}
		if int64(ct.Len()) != SealedSize(int64(n)) {
			t.Errorf("n=%d: sealed %d bytes, SealedSize says %d", n, ct.Len(), SealedSize(int64(n)))
		}
		if err := k.OpenFile(&out, bytes.NewReader(ct.Bytes())); err != nil || !bytes.Equal(out.Bytes(), pt) {
			t.Errorf("n=%d: round trip failed: %v", n, err)
		}
	}
}

func TestFileTamper(t *testing.T) {
	k := testKeys(t)
	pt := make([]byte, 2*fileChunk+100)
	rand.Read(pt)
	var ct bytes.Buffer
	k.SealFile(&ct, bytes.NewReader(pt))
	good := ct.Bytes()
	chunk2 := fileHeader + sealedChunk

	cases := map[string][]byte{
		"flipped byte":       flip(good, fileHeader+10),
		"flipped prefix":     flip(good, 5),
		"bad magic":          flip(good, 0),
		"truncated":          good[:len(good)-1],
		"final chunk gone":   good[:fileHeader+2*sealedChunk],
		"ends after chunk 1": good[:chunk2],
		"extra bytes":        append(append([]byte{}, good...), 0),
		"chunks swapped":     swap(good, fileHeader, chunk2, sealedChunk),
		"empty":              nil,
	}
	for name, c := range cases {
		if err := k.OpenFile(new(bytes.Buffer), bytes.NewReader(c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := testKeysOther(t).OpenFile(new(bytes.Buffer), bytes.NewReader(good)); err == nil {
		t.Error("another network's key opened the file")
	}
}

func testKeysOther(t *testing.T) *Keys {
	k, err := NewInvite("files").Keys()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func flip(b []byte, i int) []byte {
	c := append([]byte{}, b...)
	c[i] ^= 1
	return c
}

func swap(b []byte, i, j, n int) []byte {
	c := append([]byte{}, b...)
	copy(c[i:i+n], b[j:j+n])
	copy(c[j:j+n], b[i:i+n])
	return c
}

func TestNames(t *testing.T) {
	k := testKeys(t)
	s := k.SealName("Blür mods.zip")
	if got, err := k.OpenName(s); err != nil || got != "Blür mods.zip" {
		t.Fatalf("OpenName = %q, %v", got, err)
	}
	if k.SealName("x") == k.SealName("x") {
		t.Error("names aren't randomized")
	}
	for _, bad := range []string{"", "!!", s[:len(s)-2], testKeysOther(t).SealName("x")} {
		if _, err := k.OpenName(bad); err == nil {
			t.Errorf("OpenName(%q) accepted", bad)
		}
	}
}
