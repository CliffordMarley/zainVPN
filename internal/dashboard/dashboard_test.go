package dashboard

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"zainvpn/internal/proto"
	"zainvpn/internal/server"
)

func newTest(t *testing.T) (*Handler, *server.Server) {
	t.Helper()
	srv, err := server.New("", log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	h := New(srv, "s3cret", "v-test", 29814, log.New(io.Discard, "", 0))
	h.failDelay = 0
	return h, srv
}

func do(h http.Handler, method, path string, body io.Reader, mod func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = "192.0.2.1:1234"
	if body != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if mod != nil {
		mod(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func loginForm(pw string) io.Reader { return strings.NewReader(url.Values{"password": {pw}}.Encode()) }

func signIn(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	w := do(h, "POST", "/login", loginForm("s3cret"), nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("login: %d %q", w.Code, w.Header().Get("Location"))
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Secure {
				t.Errorf("cookie attributes: %+v", c)
			}
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func withCookie(c *http.Cookie, xrw bool) func(*http.Request) {
	return func(r *http.Request) {
		r.AddCookie(c)
		if xrw {
			r.Header.Set(csrfHeader, csrfValue)
		}
	}
}

func TestUnauthenticated(t *testing.T) {
	h, _ := newTest(t)
	if w := do(h, "GET", "/healthz", nil, nil); w.Code != 200 || strings.TrimSpace(w.Body.String()) != "ok" {
		t.Errorf("healthz: %d %q", w.Code, w.Body)
	}
	if w := do(h, "GET", "/", nil, nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Errorf("index: %d %q", w.Code, w.Header().Get("Location"))
	}
	for _, m := range []string{"GET /api/snapshot", "DELETE /api/networks/x", "GET /api/nope"} {
		method, path, _ := strings.Cut(m, " ")
		w := do(h, method, path, nil, nil)
		if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s: %d %s", m, w.Code, w.Header().Get("Content-Type"))
		}
	}
	w := do(h, "GET", "/login", nil, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `name="password"`) {
		t.Fatalf("login page: %d", w.Code)
	}
	checkNonce(t, w)
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("security headers: %v", w.Header())
	}
}

func checkNonce(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	m := regexp.MustCompile(`script-src 'nonce-([^']+)'|style-src 'nonce-([^']+)'`).FindStringSubmatch(w.Header().Get("Content-Security-Policy"))
	if m == nil {
		t.Fatalf("CSP without nonce: %q", w.Header().Get("Content-Security-Policy"))
	}
	nonce := m[1] + m[2]
	if !strings.Contains(w.Body.String(), `nonce="`+nonce+`"`) {
		t.Errorf("page doesn't carry the CSP nonce %q", nonce)
	}
	if strings.Contains(w.Body.String(), "{{") {
		t.Error("unreplaced template placeholder")
	}
}

func TestLoginFlow(t *testing.T) {
	h, _ := newTest(t)
	w := do(h, "POST", "/login", loginForm("wrong"), nil)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Incorrect password") || len(w.Result().Cookies()) != 0 {
		t.Fatalf("wrong password: %d", w.Code)
	}
	if w := do(h, "POST", "/login", loginForm(""), nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("empty password: %d", w.Code)
	}

	c := signIn(t, h)
	w = do(h, "GET", "/", nil, withCookie(c, false))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "zainVPN Coordinator") {
		t.Fatalf("index: %d", w.Code)
	}
	checkNonce(t, w)
	if w := do(h, "GET", "/login", nil, withCookie(c, false)); w.Code != http.StatusSeeOther {
		t.Errorf("login page while signed in: %d", w.Code)
	}

	w = do(h, "GET", "/api/snapshot", nil, withCookie(c, false))
	var snap struct {
		Version     string `json:"version"`
		ControlPort int    `json:"controlPort"`
		Now         string `json:"now"`
		Networks    []any  `json:"networks"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &snap) != nil || snap.Version != "v-test" || snap.ControlPort != 29814 || snap.Now == "" || snap.Networks == nil {
		t.Fatalf("snapshot: %d %s", w.Code, w.Body)
	}

	if w := do(h, "DELETE", "/api/networks/x", nil, withCookie(c, false)); w.Code != http.StatusForbidden {
		t.Errorf("DELETE without X-Requested-With: %d", w.Code)
	}
	if w := do(h, "DELETE", "/api/networks/x", nil, withCookie(c, true)); w.Code != http.StatusNotFound {
		t.Errorf("DELETE missing network: %d", w.Code)
	}
	if w := do(h, "DELETE", "/api/networks/x/devices/y", nil, withCookie(c, true)); w.Code != http.StatusNotFound {
		t.Errorf("DELETE missing device: %d", w.Code)
	}

	if w := do(h, "POST", "/logout", nil, withCookie(c, false)); w.Code != http.StatusForbidden {
		t.Errorf("logout without X-Requested-With: %d", w.Code)
	}
	if w := do(h, "POST", "/logout", nil, withCookie(c, true)); w.Code != http.StatusNoContent {
		t.Errorf("logout: %d", w.Code)
	}
	if w := do(h, "GET", "/api/snapshot", nil, withCookie(c, false)); w.Code != http.StatusUnauthorized {
		t.Errorf("snapshot after logout: %d", w.Code)
	}
}

func TestSecureCookieBehindHTTPS(t *testing.T) {
	h, _ := newTest(t)
	w := do(h, "POST", "/login", loginForm("s3cret"), func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") })
	if cs := w.Result().Cookies(); len(cs) != 1 || !cs[0].Secure {
		t.Fatalf("cookies: %+v", cs)
	}
}

func TestLockout(t *testing.T) {
	h, _ := newTest(t)
	for i := 1; i <= maxFailures; i++ {
		w := do(h, "POST", "/login", loginForm("nope"), nil)
		want := http.StatusUnauthorized
		if i == maxFailures {
			want = http.StatusTooManyRequests
		}
		if w.Code != want {
			t.Fatalf("attempt %d: %d, want %d", i, w.Code, want)
		}
	}
	w := do(h, "POST", "/login", loginForm("s3cret"), nil)
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "Try again in 5 minutes") {
		t.Fatalf("correct password while locked out: %d", w.Code)
	}
	// Other IPs are unaffected.
	if w := do(h, "POST", "/login", loginForm("s3cret"), func(r *http.Request) { r.RemoteAddr = "198.51.100.7:1" }); w.Code != http.StatusSeeOther {
		t.Fatalf("other IP: %d", w.Code)
	}
}

func TestDeleteAndRemove(t *testing.T) {
	h, srv := newTest(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); udp.Close() })
	go srv.Serve(ln, udp)

	join := func(network, device string) net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		msg, _ := json.Marshal(proto.Msg{Type: proto.MsgJoin, Version: proto.Version, Network: network,
			Auth: strings.Repeat("ab", proto.AuthLen/2), Device: device, Name: device})
		c.Write(append(msg, '\n'))
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil || !strings.Contains(line, `"welcome"`) {
			t.Fatalf("join: %q %v", line, err)
		}
		return c
	}
	join("LAN Party", "dev-a")
	join("lan party", "dev/b")
	join("other", "dev-c")

	c := signIn(t, h)
	if w := do(h, "DELETE", "/api/networks/"+url.PathEscape("lan party")+"/devices/"+url.PathEscape("dev/b"), nil, withCookie(c, true)); w.Code != 200 {
		t.Fatalf("remove device: %d %s", w.Code, w.Body)
	}
	if w := do(h, "DELETE", "/api/networks/other", nil, withCookie(c, true)); w.Code != 200 {
		t.Fatalf("delete network: %d %s", w.Code, w.Body)
	}
	snap := srv.Snapshot()
	if len(snap.Networks) != 1 || snap.Networks[0].Name != "lan party" || len(snap.Networks[0].Devices) != 1 || snap.Networks[0].Devices[0].ID != "dev-a" {
		t.Fatalf("snapshot after changes: %+v", snap)
	}
}

func fakeExe() []byte {
	b := make([]byte, 4096)
	copy(b, "MZ")
	return b
}

func TestInstallerUploadAndDownload(t *testing.T) {
	h, _ := newTest(t)
	h.EnableInstaller(filepath.Join(t.TempDir(), installerName), "", "")

	if w := do(h, "GET", "/download", nil, nil); w.Code != http.StatusNotFound {
		t.Errorf("download before upload: %d", w.Code)
	}
	if w := do(h, "GET", "/login", nil, nil); strings.Contains(w.Body.String(), "Download zainVPN") {
		t.Error("login page offers a download before one exists")
	}

	put := func(body []byte, mod func(*http.Request)) *httptest.ResponseRecorder {
		return do(h, "PUT", "/api/installer", bytes.NewReader(body), mod)
	}
	if w := put(fakeExe(), nil); w.Code != http.StatusUnauthorized {
		t.Errorf("anonymous upload: %d", w.Code)
	}
	c := signIn(t, h)
	if w := put(fakeExe(), withCookie(c, false)); w.Code != http.StatusForbidden {
		t.Errorf("upload without CSRF header: %d", w.Code)
	}
	if w := put([]byte("not an exe, just some text padding it out"), withCookie(c, true)); w.Code != http.StatusBadRequest {
		t.Errorf("non-exe upload: %d", w.Code)
	}
	bearer := func(pw string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+pw) }
	}
	if w := put(fakeExe(), bearer("wrong")); w.Code != http.StatusUnauthorized {
		t.Errorf("upload with wrong token: %d", w.Code)
	}
	if w := put(fakeExe(), bearer("s3cret")); w.Code != http.StatusOK {
		t.Fatalf("upload with token: %d %s", w.Code, w.Body)
	}

	w := do(h, "GET", "/download", nil, nil)
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), fakeExe()) {
		t.Fatalf("download: %d, %d bytes", w.Code, w.Body.Len())
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, installerName) {
		t.Errorf("Content-Disposition %q", cd)
	}
	if w := do(h, "GET", "/login", nil, nil); !strings.Contains(w.Body.String(), "Download zainVPN") || strings.Contains(w.Body.String(), "Download code") {
		t.Error("login page should offer the download without a code")
	}
	var snap struct {
		Downloads bool           `json:"downloads"`
		Installer *installerInfo `json:"installer"`
	}
	w = do(h, "GET", "/api/snapshot", nil, withCookie(c, false))
	if json.Unmarshal(w.Body.Bytes(), &snap) != nil || !snap.Downloads || snap.Installer == nil || snap.Installer.Size != 4096 {
		t.Errorf("snapshot installer: %s", w.Body)
	}
}

func TestInstallerDownloadCode(t *testing.T) {
	h, _ := newTest(t)
	path := filepath.Join(t.TempDir(), installerName)
	h.EnableInstaller(path, "", "letmein")
	if err := os.WriteFile(path, fakeExe(), 0o644); err != nil {
		t.Fatal(err)
	}
	if w := do(h, "GET", "/login", nil, nil); !strings.Contains(w.Body.String(), "Download code") {
		t.Error("login page should ask for the download code")
	}
	if w := do(h, "GET", "/download", nil, nil); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Incorrect download code") {
		t.Errorf("download without code: %d", w.Code)
	}
	if w := do(h, "GET", "/download?code=nope", nil, nil); w.Code != http.StatusUnauthorized {
		t.Errorf("download with wrong code: %d", w.Code)
	}
	if w := do(h, "GET", "/download?code=letmein", nil, nil); w.Code != 200 || w.Body.Len() != 4096 {
		t.Errorf("download with code: %d", w.Code)
	}
}
