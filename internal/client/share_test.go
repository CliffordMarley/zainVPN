package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"

	"zainvpn/internal/server"
	"zainvpn/internal/share"
)

func TestSharedFiles(t *testing.T) {
	hln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	env := newEnvWith(t, func(s *server.Server, logger *log.Logger) {
		st := share.New(dir, s, 3<<20, 1<<20, logger)
		s.SharePort = hln.Addr().(*net.TCPAddr).Port
		s.OnNetworkDeleted = st.RemoveNetwork
		hs := &http.Server{Handler: st.Handler()}
		go hs.Serve(hln)
		t.Cleanup(func() { hs.Close() })
	})
	a := env.engine("alice", "lan", "pw", false)
	b := env.engine("bob", "lan", "pw", false)
	c := env.engine("carol", "other", "pw", false)
	waitReady(t, a, b)
	waitReady(t, c)
	ctx := context.Background()

	sa, err := a.Share()
	if err != nil {
		t.Fatal(err)
	}
	sb, _ := b.Share()
	sc, _ := c.Share()

	data := make([]byte, 200<<10)
	rand.Read(data)
	if err := sa.Upload(ctx, "Blur mods.zip", int64(len(data)), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}

	l, err := sb.List(ctx)
	if err != nil || len(l.Files) != 1 {
		t.Fatalf("bob's list: %+v, %v", l, err)
	}
	f := l.Files[0]
	if f.Name != "Blur mods.zip" || f.Size != int64(len(data)) || f.By != "alice" || f.Mine || l.Quota != 3<<20 || l.MaxFile != 1<<20 {
		t.Errorf("bob sees %+v (listing %+v)", f, l)
	}
	if la, _ := sa.List(ctx); len(la.Files) != 1 || !la.Files[0].Mine {
		t.Errorf("alice's list: %+v", la)
	}

	name, size, write, err := sb.Download(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := write(&got); err != nil || name != f.Name || size != f.Size || !bytes.Equal(got.Bytes(), data) {
		t.Fatalf("download: %q %d %v, %d bytes", name, size, err, got.Len())
	}

	// Another network sees nothing and can't fetch it.
	if lc, err := sc.List(ctx); err != nil || len(lc.Files) != 0 {
		t.Errorf("carol's list: %+v, %v", lc, err)
	}
	if _, _, _, err := sc.Download(ctx, f.ID); err == nil {
		t.Error("carol downloaded another network's file")
	}

	// Limits: per file and per network.
	big := make([]byte, 1<<20+1)
	if err := sa.Upload(ctx, "big.bin", int64(len(big)), bytes.NewReader(big)); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("oversized upload: %v", err)
	}
	chunk := make([]byte, 1<<20)
	for i := 0; i < 2; i++ {
		if err := sb.Upload(ctx, "part.bin", int64(len(chunk)), bytes.NewReader(chunk)); err != nil {
			t.Fatalf("upload %d: %v", i, err)
		}
	}
	if err := sb.Upload(ctx, "part.bin", int64(len(chunk)), bytes.NewReader(chunk)); err == nil || !strings.Contains(err.Error(), "full") {
		t.Errorf("upload over quota: %v", err)
	}

	// Only the uploader can delete.
	if err := sb.Delete(ctx, f.ID); err == nil {
		t.Error("bob deleted alice's file")
	}
	if err := sa.Delete(ctx, f.ID); err != nil {
		t.Fatal(err)
	}
	if l, _ := sb.List(ctx); len(l.Files) != 2 {
		t.Errorf("after delete: %+v", l.Files)
	}

	// Deleting the network removes its folder.
	if err := env.srv.DeleteNetwork(a.keys.NetworkID); err != nil {
		t.Fatal(err)
	}
	waitReady(t, a, b)
	if sa, err = a.Share(); err != nil {
		t.Fatal(err)
	}
	if l, err := sa.List(ctx); err != nil || len(l.Files) != 0 {
		t.Errorf("after deleting the network: %+v, %v", l, err)
	}
}
