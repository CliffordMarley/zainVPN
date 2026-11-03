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
	Apply(client.Config) error // save and reconnect
	Logs() []string
}

type publicConfig struct {
	Server      string `json:"server"`
	Network     string `json:"network"`
	Name        string `json:"name"`
	HasPassword bool   `json:"hasPassword"`
}

type statusResponse struct {
	Status  client.Status `json:"status"`
	Version string        `json:"version"`
	Config  publicConfig  `json:"config"` // never the password
}

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
			Server   string `json:"server"`
			Network  string `json:"network"`
			Name     string `json:"name"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		cur := b.Config()
		next := cur
		next.Server = strings.TrimSpace(req.Server)
		next.Network = strings.TrimSpace(req.Network)
		next.Name = strings.TrimSpace(req.Name)
		if req.Password != "" {
			next.Password = req.Password
		} else if cur.Password == "" || proto.NormalizeNetwork(next.Network) != proto.NormalizeNetwork(cur.Network) {
			writeError(w, http.StatusBadRequest, "Enter the password for this network.")
			return
		}
		if err := checkName(next.Name); err != nil {
			writeError(w, http.StatusBadRequest, sentence(err))
			return
		}
		ensureIdentity(&next)
		if err := validateConfig(next); err != nil {
			writeError(w, http.StatusBadRequest, sentence(err))
			return
		}
		if err := b.Apply(next); err != nil {
			writeError(w, http.StatusInternalServerError, sentence(err))
			return
		}
		writeJSON(w, http.StatusOK, statusOf(b))
	})
	return &http.Server{Handler: guard(mux), ReadHeaderTimeout: 10 * time.Second, ErrorLog: logger}
}

func statusOf(b backend) statusResponse {
	c := b.Config()
	return statusResponse{
		Status: b.Status(), Version: version,
		Config: publicConfig{Server: c.Server, Network: c.Network, Name: c.Name, HasPassword: c.Password != ""},
	}
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
// without admin rights or an adapter.
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
		Server: "vpn.example.com", Network: "blur-night", Password: "demo", Name: computerName(), DeviceID: "demo",
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
	st := client.Status{
		State: client.StateOnline, IP: "10.77.0.2", Name: d.cfg.Name, Network: d.cfg.Network,
		Server: d.cfg.Server, Relay: true, Peers: []client.PeerStatus{},
	}
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

// Apply only updates the in-memory settings; nothing is saved.
func (d *demo) Apply(c client.Config) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg, d.changed = c, time.Now()
	return nil
}

func (d *demo) Logs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	ts := func(sec int) string { return d.t0.Add(time.Duration(sec) * time.Second).Format("2006/01/02 15:04:05") }
	return []string{
		ts(0) + " zainVPN " + version + " starting",
		ts(0) + " dashboard at http://" + uiAddr + "/",
		ts(1) + ` adapter "zainVPN" ready`,
		ts(1) + " adapter address 10.77.0.2/24",
		ts(1) + fmt.Sprintf(" online as 10.77.0.2 in %q", d.cfg.Network),
		ts(2) + " direct path to Zain (10.77.0.3) via 203.0.113.24:41641, 23ms",
		ts(6) + " network profile set to Private",
	}
}
