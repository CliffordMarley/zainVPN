//go:build windows

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
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
	return &http.Server{Handler: guard(mux), ReadHeaderTimeout: 10 * time.Second, ErrorLog: logger}
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
			mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if r.Header.Get("X-ZainVPN") != "1" || mt != "application/json" {
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
