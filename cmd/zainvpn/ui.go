//go:build windows

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"zainvpn/internal/client"
	"zainvpn/internal/proto"
)

//go:embed ui/index.html
var indexHTML []byte

// backend is what the UI shows and changes: the real VPN or the demo.
type backend interface {
	Status() client.Status
	Config() client.Config
	// Update changes the settings with fn, saves them and reconnects. If fn
	// fails, nothing changes and its error is returned as is.
	Update(fn func(*client.Config) error) error
	Logs() []string
	// Share is the current network's shared folder, while connected.
	Share() (shareAPI, error)
}

// shareAPI is the shared folder (*client.Share, or the demo's).
type shareAPI interface {
	List(ctx context.Context) (client.ShareListing, error)
	Upload(ctx context.Context, name string, size int64, r io.Reader) error
	Download(ctx context.Context, id string) (name string, size int64, write func(io.Writer) error, err error)
	Delete(ctx context.Context, id string) error
}

type publicConfig struct {
	Server    string `json:"server"`
	Name      string `json:"name"`
	InNetwork bool   `json:"inNetwork"`
}

type statusResponse struct {
	Status  client.Status `json:"status"` // includes the invite code, for sharing it
	Version string        `json:"version"`
	Config  publicConfig  `json:"config"`
}

// networkResponse answers /api/network: the new status, plus the code of
// the network just created or joined.
type networkResponse struct {
	Invite string `json:"invite,omitempty"`
	statusResponse
}

// apiError is an error the UI shows as is, with its HTTP status.
type apiError struct {
	code int
	msg  string
}

func (e *apiError) Error() string { return e.msg }

func badRequest(msg string) error { return &apiError{http.StatusBadRequest, msg} }

func newUIServer(b backend, logger *log.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "+
			"img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		w.Write(indexHTML)
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, statusOf(b))
	})
	mux.HandleFunc("GET /api/logs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string][]string{"lines": b.Logs()})
	})
	mux.HandleFunc("POST /api/config", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Server string `json:"server"`
			Name   string `json:"name"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		err := b.Update(func(c *client.Config) error {
			c.Server = strings.TrimSpace(req.Server)
			c.Name = strings.TrimSpace(req.Name)
			if err := checkName(c.Name); err != nil {
				return badRequest(sentence(err))
			}
			ensureIdentity(c)
			if err := validateConfig(*c); err != nil {
				return badRequest(sentence(err))
			}
			return nil
		})
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, statusOf(b))
	})
	mux.HandleFunc("POST /api/network", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Action string `json:"action"` // "create", "join" or "leave"
			Name   string `json:"name"`   // create: the network's name
			Code   string `json:"code"`   // join: the invite code
		}
		if !readJSON(w, r, &req) {
			return
		}
		var inv proto.Invite
		enter := func(c *client.Config) error {
			if c.Invite != "" && c.Invite != inv.String() {
				return &apiError{http.StatusConflict, "You're already in a network. Leave it first to create or join another one."}
			}
			if c.Server == "" {
				return badRequest("Enter the coordinator address in Settings first.")
			}
			if err := checkServer(c.Server); err != nil {
				return badRequest(sentence(err))
			}
			c.Invite = inv.String()
			ensureIdentity(c)
			return nil
		}
		var err error
		switch req.Action {
		case "create":
			name := strings.TrimSpace(req.Name)
			switch {
			case name == "":
				err = badRequest("Enter a name for your network.")
			case !strings.ContainsFunc(strings.ToLower(name), isLabelChar):
				err = badRequest("Use letters (a-z) or numbers in the network name.")
			default:
				inv = proto.NewInvite(name)
				err = b.Update(enter)
			}
		case "join":
			if strings.TrimSpace(req.Code) == "" {
				err = badRequest("Paste the invite code a friend sent you.")
			} else if inv, err = proto.ParseInvite(req.Code); err != nil {
				err = badRequest(sentence(err))
			} else {
				err = b.Update(enter) // joining the network you're in is a no-op
			}
		case "leave":
			err = b.Update(func(c *client.Config) error {
				c.Invite = ""
				return nil
			})
		default:
			err = badRequest("Unknown action.")
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		resp := networkResponse{statusResponse: statusOf(b)}
		if inv.Secret != "" {
			resp.Invite = inv.String()
		}
		writeJSON(w, http.StatusOK, resp)
	})
	addShareRoutes(mux, b)
	return &http.Server{Handler: guard(mux), ReadHeaderTimeout: 10 * time.Second, ErrorLog: logger}
}

// addShareRoutes serves the shared folder to the UI. The service encrypts
// uploads and decrypts downloads; the coordinator only sees ciphertext.
func addShareRoutes(mux *http.ServeMux, b backend) {
	mux.HandleFunc("GET /api/share", func(w http.ResponseWriter, r *http.Request) {
		type resp struct {
			Available bool   `json:"available"`
			Message   string `json:"message,omitempty"`
			client.ShareListing
		}
		s, err := b.Share()
		if err != nil {
			writeJSON(w, http.StatusOK, resp{Message: sentence(err), ShareListing: client.ShareListing{Files: []client.SharedFile{}}})
			return
		}
		l, err := s.List(r.Context())
		if err != nil {
			writeJSON(w, http.StatusOK, resp{Message: sentence(err), ShareListing: client.ShareListing{Files: []client.SharedFile{}}})
			return
		}
		writeJSON(w, http.StatusOK, resp{Available: true, ShareListing: l})
	})
	mux.HandleFunc("POST /api/share/upload", func(w http.ResponseWriter, r *http.Request) {
		name := fileBase(r.URL.Query().Get("name"))
		switch {
		case name == "":
			writeError(w, http.StatusBadRequest, "Choose a file to upload.")
			return
		case r.ContentLength < 0:
			writeError(w, http.StatusLengthRequired, "The file size is missing.")
			return
		}
		s, err := b.Share()
		if err == nil {
			err = s.Upload(r.Context(), name, r.ContentLength, r.Body)
		}
		if err != nil {
			writeError(w, http.StatusBadGateway, sentence(err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"name": name})
	})
	mux.HandleFunc("GET /api/share/files/{id}", func(w http.ResponseWriter, r *http.Request) {
		s, err := b.Share()
		var name string
		var size int64
		var write func(io.Writer) error
		if err == nil {
			name, size, write, err = s.Download(r.Context(), r.PathValue("id"))
		}
		if err != nil {
			http.Error(w, sentence(err), http.StatusBadGateway)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
		if size > 0 {
			h.Set("Content-Length", strconv.FormatInt(size, 10))
		}
		if err := write(w); err != nil {
			// Headers are gone; aborting makes the browser report a failed download.
			panic(http.ErrAbortHandler)
		}
	})
	mux.HandleFunc("POST /api/share/delete", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID string `json:"id"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		s, err := b.Share()
		if err == nil {
			err = s.Delete(r.Context(), req.ID)
		}
		if err != nil {
			writeError(w, http.StatusBadGateway, sentence(err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
}

// fileBase keeps only the file name from a path someone typed or uploaded.
func fileBase(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || strings.ContainsRune(`<>:"|?*`, r) {
			return -1
		}
		return r
	}, strings.TrimSpace(name))
	if len(name) > 200 {
		name = name[:200]
	}
	return strings.Trim(name, ". ")
}

// isLabelChar reports whether network names keep r (see proto.CleanLabel).
func isLabelChar(r rune) bool { return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' }

func statusOf(b backend) statusResponse {
	c := b.Config()
	return statusResponse{
		Status: b.Status(), Version: version,
		Config: publicConfig{Server: c.Server, Name: c.Name, InNetwork: c.Invite != ""},
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request.")
		return false
	}
	return true
}

// guard protects the local API from other websites: DNS rebinding (checked
// via Host) and cross-site requests (a custom header plus a JSON content
// type force a CORS preflight, which we never approve).
func guard(next http.Handler) http.Handler {
	hosts := map[string]bool{"127.0.0.1:7779": true, "localhost:7779": true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hosts[strings.ToLower(r.Host)] {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !hosts[strings.TrimPrefix(strings.ToLower(o), "http://")] {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Uploads send raw bytes; octet-stream also forces a preflight.
			mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			upload := r.URL.Path == "/api/share/upload" && mt == "application/octet-stream"
			if r.Header.Get("X-ZainVPN") != "1" || (mt != "application/json" && !upload) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// writeErr sends an apiError as is, and anything else as a server error.
func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeError(w, ae.code, ae.msg)
		return
	}
	writeError(w, http.StatusInternalServerError, sentence(err))
}

// sentence capitalizes an error message for display.
func sentence(err error) string {
	s := err.Error()
	if s == "" {
		return s
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// serveUI runs the dashboard until ctx is cancelled. If the port is taken it
// keeps retrying instead of failing: the VPN works without the UI.
func serveUI(ctx context.Context, b backend, logger *log.Logger) {
	srv := newUIServer(b, logger)
	stop := context.AfterFunc(ctx, func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	})
	defer stop()
	for ctx.Err() == nil {
		ln, err := net.Listen("tcp4", uiAddr)
		if err == nil {
			logger.Printf("dashboard at http://%s/", uiAddr)
			if err = srv.Serve(ln); errors.Is(err, http.ErrServerClosed) {
				return
			}
		}
		logger.Printf("dashboard: %v (retrying in 10s)", err)
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
	}
}

// cmdUIDemo serves the real UI with fake data, for previewing the design
// without admin rights or an adapter. It starts outside any network;
// creating or joining one shows fake friends.
func cmdUIDemo(args []string) error {
	fl := flag.NewFlagSet("ui-demo", flag.ContinueOnError)
	empty := fl.Bool("empty", false, "show no other players")
	if err := fl.Parse(args); err != nil {
		return errUsage
	}
	ln, err := net.Listen("tcp4", uiAddr)
	if err != nil {
		return fmt.Errorf("%w (is the zainVPN service running? stop it with \"zainvpn stop\")", err)
	}
	fmt.Printf("zainVPN dashboard demo with fake data at http://%s/ (Ctrl+C to stop)\n", uiAddr)
	d := &demo{t0: time.Now(), changed: time.Now(), empty: *empty, cfg: client.Config{
		Server: "vpn.example.com", Name: computerName(), DeviceID: "demo",
	}}
	srv := newUIServer(d, log.New(os.Stderr, "", log.LstdFlags))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	context.AfterFunc(ctx, func() { srv.Close() })
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type demo struct {
	mu      sync.Mutex
	cfg     client.Config
	t0      time.Time
	changed time.Time
	empty   bool
	files   []demoFile
}

type demoFile struct {
	client.SharedFile
	data []byte
}

// Share is an in-memory shared folder, seeded with a file from a friend.
func (d *demo) Share() (shareAPI, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := proto.ParseInvite(d.cfg.Invite); err != nil {
		return nil, client.ErrShareUnavailable
	}
	if d.files == nil {
		d.files = []demoFile{{SharedFile: client.SharedFile{
			ID: "0001", Name: "Blur LAN tips.txt", Size: 46, By: "Zain", Uploaded: time.Now().Add(-time.Hour),
		}, data: []byte("Host picks the track, everyone else joins LAN.")}}
	}
	return demoShare{d}, nil
}

type demoShare struct{ d *demo }

func (s demoShare) List(ctx context.Context) (client.ShareListing, error) {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	l := client.ShareListing{Files: []client.SharedFile{}, Quota: 10 << 30, MaxFile: 2 << 30}
	for i := len(s.d.files) - 1; i >= 0; i-- {
		l.Files = append(l.Files, s.d.files[i].SharedFile)
		l.Used += s.d.files[i].Size
	}
	return l, nil
}

func (s demoShare) Upload(ctx context.Context, name string, size int64, r io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(r, min(size, 64<<20)))
	if err != nil {
		return err
	}
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	id := fmt.Sprintf("%04d", len(s.d.files)+1)
	s.d.files = append(s.d.files, demoFile{client.SharedFile{
		ID: id, Name: name, Size: size, By: s.d.cfg.Name, Mine: true, Uploaded: time.Now(),
	}, data})
	return nil
}

func (s demoShare) Download(ctx context.Context, id string) (string, int64, func(io.Writer) error, error) {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	for _, f := range s.d.files {
		if f.ID == id {
			data := f.data
			return f.Name, int64(len(data)), func(w io.Writer) error { _, err := w.Write(data); return err }, nil
		}
	}
	return "", 0, nil, errors.New("file not found")
}

func (s demoShare) Delete(ctx context.Context, id string) error {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	for i, f := range s.d.files {
		if f.ID == id {
			if !f.Mine {
				return errors.New("only " + f.By + " can delete this file")
			}
			s.d.files = append(s.d.files[:i], s.d.files[i+1:]...)
			return nil
		}
	}
	return errors.New("file not found")
}

func (d *demo) Status() client.Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := client.Status{State: stateSetup, Message: setupMessage, Name: d.cfg.Name, Server: d.cfg.Server, Peers: []client.PeerStatus{}}
	inv, err := proto.ParseInvite(d.cfg.Invite)
	if err != nil {
		return st
	}
	st.State, st.Message, st.IP, st.Relay = client.StateOnline, "", "10.77.0.2", true
	st.Network, st.Invite = inv.Label, inv.String()
	if time.Since(d.changed) < 3*time.Second {
		st.State, st.IP, st.Relay = client.StateConnecting, "", false
		return st
	}
	if d.empty {
		return st
	}
	t := time.Since(d.t0).Seconds()
	wobble := func(base, amp, phase float64) float64 {
		return math.Round((base+amp*math.Sin(t/4+phase))*10) / 10
	}
	st.Peers = []client.PeerStatus{
		{Name: "Zain", IP: "10.77.0.3", Online: true, Path: "direct", RTTms: wobble(24, 3, 0), Endpoint: "203.0.113.24:41641"},
		{Name: "Ali", IP: "10.77.0.4", Online: true, Path: "relay", RTTms: wobble(68, 6, 2)},
		{Name: "Sara", IP: "10.77.0.5", Online: false, Path: "offline", RTTms: -1},
	}
	return st
}

func (d *demo) Config() client.Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg
}

// Update only changes the in-memory settings; nothing is saved.
func (d *demo) Update(fn func(*client.Config) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.cfg
	if err := fn(&c); err != nil {
		return err
	}
	if c != d.cfg {
		d.cfg, d.changed = c, time.Now()
	}
	return nil
}

func (d *demo) Logs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	ts := func(t time.Time, sec int) string {
		return t.Add(time.Duration(sec) * time.Second).Format("2006/01/02 15:04:05")
	}
	lines := []string{
		ts(d.t0, 0) + " zainVPN " + version + " starting",
		ts(d.t0, 0) + " dashboard at http://" + uiAddr + "/",
		ts(d.t0, 1) + ` adapter "zainVPN" ready`,
	}
	if inv, err := proto.ParseInvite(d.cfg.Invite); err == nil {
		lines = append(lines,
			ts(d.changed, 0)+fmt.Sprintf(" settings changed: network %q, coordinator %s, nickname %q", inv.Label, d.cfg.Server, d.cfg.Name),
			ts(d.changed, 3)+" adapter address 10.77.0.2/24",
			ts(d.changed, 3)+fmt.Sprintf(" online as 10.77.0.2 in %q", inv.Label),
			ts(d.changed, 4)+" direct path to Zain (10.77.0.3) via 203.0.113.24:41641, 23ms",
			ts(d.changed, 8)+" network profile set to Private",
		)
	}
	return lines
}
