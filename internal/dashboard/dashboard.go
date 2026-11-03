// Package dashboard serves the coordinator's password-protected admin web UI
// and its small JSON API.
package dashboard

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"zainvpn/internal/server"
)

var (
	//go:embed index.html
	indexHTML []byte
	//go:embed login.html
	loginSrc  string
	loginTmpl = template.Must(template.New("login").Parse(loginSrc))
)

const (
	cookieName  = "zv_session"
	sessionTTL  = 12 * time.Hour
	maxSessions = 64
	maxFailures = 10               // failed sign-ins from one IP...
	failWindow  = 15 * time.Minute // ...within this window...
	lockout     = 5 * time.Minute  // ...lock that IP out for this long
	csrfHeader  = "X-Requested-With"
	csrfValue   = "zainvpn"

	installerName = "zainVPN-Setup.exe"
	maxInstaller  = 100 << 20
	transferTime  = 10 * time.Minute // upload/download deadline, past the server's 30s default
)

// Handler is the dashboard's http.Handler.
type Handler struct {
	srv         *server.Server
	pwHash      [32]byte
	pwSet       bool
	version     string
	controlPort int
	log         *log.Logger
	mux         *http.ServeMux
	failDelay   time.Duration // tests set this to 0

	installer    string   // path of the uploaded installer; "" disables downloads
	downloadHash [32]byte // sha256 of the optional download code
	downloadCode bool

	mu       sync.Mutex
	sessions map[[32]byte]time.Time // sha256(token) -> expiry
	failures map[string]*failures   // by client IP
}

type failures struct {
	n     int
	last  time.Time
	until time.Time
}

// New returns the dashboard for srv. controlPort is the coordinator's
// TCP/UDP port, shown to the admin as the address clients connect to.
func New(srv *server.Server, adminPassword, version string, controlPort int, logger *log.Logger) *Handler {
	h := &Handler{
		srv:         srv,
		pwHash:      sha256.Sum256([]byte(adminPassword)),
		pwSet:       adminPassword != "",
		version:     version,
		controlPort: controlPort,
		log:         logger,
		failDelay:   time.Second,
		sessions:    map[[32]byte]time.Time{},
		failures:    map[string]*failures{},
	}
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})
	m.HandleFunc("GET /login", h.loginPage)
	m.HandleFunc("POST /login", h.login)
	m.HandleFunc("POST /logout", h.logout)
	m.HandleFunc("GET /{$}", h.index)
	m.HandleFunc("GET /download", h.download)
	m.HandleFunc("GET /api/snapshot", h.api(h.snapshot))
	m.HandleFunc("PUT /api/installer", h.api(h.uploadInstaller))
	m.HandleFunc("DELETE /api/networks/{name}", h.api(h.deleteNetwork))
	m.HandleFunc("DELETE /api/networks/{name}/devices/{id}", h.api(h.removeDevice))
	m.HandleFunc("/api/", h.api(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, errBody("not found"))
	}))
	m.HandleFunc("/", http.NotFound)
	h.mux = m
	return h
}

// EnableInstaller lets the admin upload the Windows installer, stored at
// path, and lets anyone download it from the sign-in page. A non-empty code
// must then be entered to download it.
func (h *Handler) EnableInstaller(path, code string) {
	h.installer = path
	h.downloadHash = sha256.Sum256([]byte(code))
	h.downloadCode = code != ""
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("Cache-Control", "no-store")
	h.mux.ServeHTTP(w, r)
}

// htmlHeaders sets a nonce-based CSP for a page and returns the nonce.
func htmlHeaders(w http.ResponseWriter) string {
	var b [18]byte
	rand.Read(b[:])
	// URL-safe alphabet: html/template would write a '+' as "&#43;" in the
	// login page's nonce attribute.
	nonce := base64.RawURLEncoding.EncodeToString(b[:])
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; script-src 'nonce-%[1]s'; style-src 'nonce-%[1]s'; img-src 'self' data:; "+
			"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'", nonce))
	return nonce
}

func (h *Handler) index(w http.ResponseWriter, r *http.Request) {
	if !h.authed(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	nonce := htmlHeaders(w)
	w.Write(bytes.ReplaceAll(indexHTML, []byte("{{NONCE}}"), []byte(nonce)))
}

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	if h.authed(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	h.renderLogin(w, http.StatusOK, "")
}

func (h *Handler) renderLogin(w http.ResponseWriter, status int, msg string) {
	h.renderLoginPage(w, status, msg, "")
}

func (h *Handler) renderLoginPage(w http.ResponseWriter, status int, msg, downloadErr string) {
	nonce := htmlHeaders(w)
	w.WriteHeader(status)
	err := loginTmpl.Execute(w, struct {
		Nonce, Error, Version, DownloadError string
		Installer                            *installerInfo
		NeedCode                             bool
	}{nonce, msg, h.version, downloadErr, h.installerInfo(), h.downloadCode})
	if err != nil {
		h.log.Printf("dashboard: login page: %v", err)
	}
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if wait := h.lockedFor(ip); wait > 0 {
		h.renderLogin(w, http.StatusTooManyRequests, lockedMsg(wait))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	got := sha256.Sum256([]byte(r.PostFormValue("password")))
	if !h.pwSet || subtle.ConstantTimeCompare(got[:], h.pwHash[:]) != 1 {
		locked := h.recordFailure(ip)
		h.log.Printf("dashboard: failed sign-in from %s", ip)
		time.Sleep(h.failDelay)
		if locked {
			h.log.Printf("dashboard: locked out %s for %s after %d failed sign-ins", ip, lockout, maxFailures)
			h.renderLogin(w, http.StatusTooManyRequests, lockedMsg(lockout))
			return
		}
		h.renderLogin(w, http.StatusUnauthorized, "Incorrect password. Try again.")
		return
	}

	h.mu.Lock()
	delete(h.failures, ip)
	h.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    h.newSession(),
		Path:     "/",
		MaxAge:   int(sessionTTL / time.Second),
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteStrictMode,
	})
	h.log.Printf("dashboard: signed in from %s", ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(csrfHeader) != csrfValue {
		writeJSON(w, http.StatusForbidden, errBody("missing "+csrfHeader+" header"))
		return
	}
	if c, err := r.Cookie(cookieName); err == nil {
		h.mu.Lock()
		delete(h.sessions, sha256.Sum256([]byte(c.Value)))
		h.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

// api requires a session, plus the CSRF header on anything but reads.
// Scripts (build.ps1 -Publish) may instead send "Authorization: Bearer
// <admin password>", which browsers never add on their own, so no CSRF check.
func (h *Handler) api(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if pw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			ip := clientIP(r)
			if h.lockedFor(ip) > 0 {
				writeJSON(w, http.StatusTooManyRequests, errBody("too many failed attempts, try again later"))
				return
			}
			got := sha256.Sum256([]byte(pw))
			if !h.pwSet || subtle.ConstantTimeCompare(got[:], h.pwHash[:]) != 1 {
				h.recordFailure(ip)
				h.log.Printf("dashboard: bad API token from %s", ip)
				time.Sleep(h.failDelay)
				writeJSON(w, http.StatusUnauthorized, errBody("wrong admin password"))
				return
			}
			next(w, r)
			return
		}
		if !h.authed(r) {
			writeJSON(w, http.StatusUnauthorized, errBody("not signed in"))
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(csrfHeader) != csrfValue {
			writeJSON(w, http.StatusForbidden, errBody("missing "+csrfHeader+" header"))
			return
		}
		next(w, r)
	}
}

func (h *Handler) snapshot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		server.Snapshot
		Version      string         `json:"version"`
		ControlPort  int            `json:"controlPort"`
		Now          time.Time      `json:"now"`
		Downloads    bool           `json:"downloads"`
		DownloadCode bool           `json:"downloadCode"`
		Installer    *installerInfo `json:"installer"`
	}{h.srv.Snapshot(), h.version, h.controlPort, time.Now().UTC(), h.installer != "", h.downloadCode, h.installerInfo()})
}

type installerInfo struct {
	Size     int64     `json:"size"`
	Uploaded time.Time `json:"uploaded"`
}

// Human-readable forms for the sign-in page template.
func (i *installerInfo) SizeText() string { return fmt.Sprintf("%.1f MB", float64(i.Size)/(1<<20)) }
func (i *installerInfo) DateText() string { return i.Uploaded.Format("2 Jan 2006") }

// installerInfo describes the uploaded installer, or returns nil if there is none.
func (h *Handler) installerInfo() *installerInfo {
	if h.installer == "" {
		return nil
	}
	fi, err := os.Stat(h.installer)
	if err != nil {
		return nil
	}
	return &installerInfo{Size: fi.Size(), Uploaded: fi.ModTime().UTC()}
}

// download serves the installer to anyone (it's how friends get zainVPN),
// after checking the download code if one is configured.
func (h *Handler) download(w http.ResponseWriter, r *http.Request) {
	if h.installerInfo() == nil {
		http.Error(w, "No installer has been uploaded yet. Ask your group's admin.", http.StatusNotFound)
		return
	}
	if h.downloadCode {
		ip := clientIP(r)
		if wait := h.lockedFor(ip); wait > 0 {
			h.renderLoginPage(w, http.StatusTooManyRequests, "", lockedMsg(wait))
			return
		}
		got := sha256.Sum256([]byte(r.URL.Query().Get("code")))
		if subtle.ConstantTimeCompare(got[:], h.downloadHash[:]) != 1 {
			h.recordFailure(ip)
			time.Sleep(h.failDelay)
			h.renderLoginPage(w, http.StatusUnauthorized, "", "Incorrect download code.")
			return
		}
	}
	f, err := os.Open(h.installer)
	if err != nil {
		http.Error(w, "installer unavailable", http.StatusNotFound)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		http.Error(w, "installer unavailable", http.StatusInternalServerError)
		return
	}
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(transferTime))
	w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
	w.Header().Set("Content-Disposition", `attachment; filename="`+installerName+`"`)
	h.log.Printf("dashboard: installer downloaded by %s", clientIP(r))
	http.ServeContent(w, r, installerName, fi.ModTime(), f)
}

// uploadInstaller replaces the installer with the request body (a raw .exe).
func (h *Handler) uploadInstaller(w http.ResponseWriter, r *http.Request) {
	if h.installer == "" {
		writeJSON(w, http.StatusNotFound, errBody("installer downloads are disabled"))
		return
	}
	http.NewResponseController(w).SetReadDeadline(time.Now().Add(transferTime))
	tmp, err := os.CreateTemp(filepath.Dir(h.installer), ".upload-*")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, http.MaxBytesReader(w, r.Body, maxInstaller))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("upload failed: "+err.Error()))
		return
	}
	head := make([]byte, 2)
	if f, err := os.Open(tmp.Name()); err == nil {
		io.ReadFull(f, head)
		f.Close()
	}
	if n < 1024 || string(head) != "MZ" {
		writeJSON(w, http.StatusBadRequest, errBody("that isn't a Windows .exe file"))
		return
	}
	if err := os.Rename(tmp.Name(), h.installer); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	h.log.Printf("dashboard: installer uploaded from %s (%d bytes)", clientIP(r), n)
	writeJSON(w, http.StatusOK, h.installerInfo())
}

func (h *Handler) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	h.result(w, h.srv.DeleteNetwork(name))
}

func (h *Handler) removeDevice(w http.ResponseWriter, r *http.Request) {
	h.result(w, h.srv.RemoveDevice(r.PathValue("name"), r.PathValue("id")))
}

func (h *Handler) result(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case errors.Is(err, server.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errBody("not found"))
	default:
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
	}
}

func (h *Handler) newSession() string {
	var b [32]byte
	rand.Read(b[:])
	token := hex.EncodeToString(b[:])
	now := time.Now()

	h.mu.Lock()
	defer h.mu.Unlock()
	var oldest [32]byte
	var oldestExp time.Time
	for k, exp := range h.sessions {
		if now.After(exp) {
			delete(h.sessions, k)
		} else if oldestExp.IsZero() || exp.Before(oldestExp) {
			oldest, oldestExp = k, exp
		}
	}
	if len(h.sessions) >= maxSessions {
		delete(h.sessions, oldest)
	}
	h.sessions[sha256.Sum256([]byte(token))] = now.Add(sessionTTL)
	return token
}

func (h *Handler) authed(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil || len(c.Value) != 64 {
		return false
	}
	key := sha256.Sum256([]byte(c.Value))
	h.mu.Lock()
	defer h.mu.Unlock()
	exp, ok := h.sessions[key]
	if ok && time.Now().After(exp) {
		delete(h.sessions, key)
		return false
	}
	return ok
}

func (h *Handler) lockedFor(ip string) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	if f := h.failures[ip]; f != nil {
		return time.Until(f.until)
	}
	return 0
}

// recordFailure counts a failed sign-in and reports whether it locked the IP out.
func (h *Handler) recordFailure(ip string) bool {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.failures) > 1000 {
		for k, f := range h.failures {
			if now.Sub(f.last) > failWindow && now.After(f.until) {
				delete(h.failures, k)
			}
		}
	}
	f := h.failures[ip]
	if f == nil || now.Sub(f.last) > failWindow {
		f = &failures{}
		h.failures[ip] = f
	}
	f.n++
	f.last = now
	if f.n >= maxFailures {
		f.n = 0
		f.until = now.Add(lockout)
		return true
	}
	return false
}

func lockedMsg(wait time.Duration) string {
	mins := int((wait + time.Minute - 1) / time.Minute)
	unit := "minutes"
	if mins == 1 {
		unit = "minute"
	}
	return fmt.Sprintf("Too many failed sign-in attempts. Try again in %d %s.", mins, unit)
}

// clientIP is the TCP peer address. X-Forwarded-For is ignored because the
// dashboard is normally reached directly, where that header can be forged.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func errBody(msg string) map[string]string { return map[string]string{"error": msg} }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
