//go:build windows

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zainvpn/internal/client"
	"zainvpn/internal/proto"
)

func TestConfigBOMAndIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	// UTF-8 BOM, CRLF, no deviceId or name, and the old network/password fields (ignored).
	in := "\xef\xbb\xbf{\r\n  \"server\": \" 203.0.113.10 \",\r\n  \"network\": \"Blur\",\r\n  \"password\": \"pw\"\r\n}\r\n"
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "203.0.113.10" || c.Invite != "" {
		t.Fatalf("loaded %+v", c)
	}
	if !ensureIdentity(&c) || len(c.DeviceID) != 32 || c.Name == "" {
		t.Fatalf("identity not filled: %+v", c)
	}
	id := c.DeviceID
	if ensureIdentity(&c) {
		t.Fatal("ensureIdentity changed a complete config")
	}
	if err := saveConfig(path, c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
	c2, err := loadConfig(path)
	if err != nil || c2 != c || c2.DeviceID != id {
		t.Fatalf("round trip: %+v, %v", c2, err)
	}
	long := client.Config{Name: strings.Repeat("é", 40), DeviceID: "x"}
	ensureIdentity(&long)
	if checkName(long.Name) != nil {
		t.Fatal("over-long name not truncated")
	}
}

func TestCheckServer(t *testing.T) {
	for _, s := range []string{"203.0.113.10", "vpn.example.com", "vpn.example.com:29814", "1.2.3.4:1"} {
		if err := checkServer(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "http://x.com", "x.com:0", "x.com:99999", "x y", "x.com/path", "::1", "user@x.com"} {
		if checkServer(s) == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestUIGuardAndConfig(t *testing.T) {
	inv := proto.NewInvite("blur").String()
	d := &demo{t0: time.Now(), cfg: client.Config{Server: "s", Invite: inv, Name: "me", DeviceID: "d"}}
	h := newUIServer(d, nil).Handler
	do := func(method, host, body string, hdr map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://"+host+"/api/config", strings.NewReader(body))
		if method == http.MethodGet {
			r = httptest.NewRequest(method, "http://"+host+"/api/status", nil)
		}
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	ok := map[string]string{"X-ZainVPN": "1", "Content-Type": "application/json"}

	if w := do("GET", "127.0.0.1:7779", "", nil); w.Code != 200 {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
	if w := do("GET", "evil.com", "", nil); w.Code != 403 {
		t.Fatalf("rebinding host: %d", w.Code)
	}
	if w := do("POST", "localhost:7779", `{}`, map[string]string{"Content-Type": "application/json"}); w.Code != 403 {
		t.Fatalf("missing header: %d", w.Code)
	}
	if w := do("POST", "127.0.0.1:7779", `{}`, map[string]string{"X-ZainVPN": "1", "Content-Type": "text/plain"}); w.Code != 403 {
		t.Fatalf("text/plain: %d", w.Code)
	}
	if w := do("POST", "127.0.0.1:7779", `{"server":"s2:29814","name":"me2"}`, ok); w.Code != 200 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	if c := d.Config(); c.Server != "s2:29814" || c.Invite != inv || c.Name != "me2" || c.DeviceID != "d" {
		t.Fatalf("applied %+v", c)
	}
}

func TestUINetworkActions(t *testing.T) {
	d := &demo{t0: time.Now(), cfg: client.Config{Server: "s", Name: "me", DeviceID: "d"}}
	h := newUIServer(d, nil).Handler
	act := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://127.0.0.1:7779/api/network", strings.NewReader(body))
		r.Header.Set("X-ZainVPN", "1")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	var resp struct{ Invite string }
	w := act(`{"action":"create","name":"Blur Night"}`)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &resp) != nil || !strings.HasPrefix(resp.Invite, "blur-night-") {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if d.Config().Invite != resp.Invite {
		t.Fatalf("invite not saved: %+v", d.Config())
	}
	if w := act(`{"action":"create","name":"other"}`); w.Code != 409 {
		t.Fatalf("create while in a network: %d", w.Code)
	}
	if w := act(`{"action":"leave"}`); w.Code != 200 || d.Config().Invite != "" {
		t.Fatalf("leave: %d %+v", w.Code, d.Config())
	}
	if w := act(`{"action":"join","code":"blur-AAAA-BBBB-CCCC"}`); w.Code != 400 || !strings.Contains(w.Body.String(), "invite code") {
		t.Fatalf("bad code: %d %s", w.Code, w.Body)
	}
	if w := act(`{"action":"join","code":" ` + strings.ToLower(resp.Invite) + ` "}`); w.Code != 200 || d.Config().Invite != resp.Invite {
		t.Fatalf("join: %d %s %+v", w.Code, w.Body, d.Config())
	}
}
