// Command zainvpn-server is the zainVPN coordinator: it admits clients to
// networks over TCP, relays UDP between peers that can't connect directly,
// and serves an admin dashboard over HTTP.
//
// Every setting comes from an environment variable and can be overridden by
// the matching flag (see -help).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"zainvpn/internal/dashboard"
	"zainvpn/internal/server"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const udpBuffer = 4 << 20

type config struct {
	listen        string
	http          string
	state         string
	adminPassword string
}

func main() {
	var cfg config
	flag.StringVar(&cfg.listen, "listen", envOr("ZAINVPN_LISTEN", ":29814"), "TCP and UDP `address` for clients (env ZAINVPN_LISTEN)")
	flag.StringVar(&cfg.http, "http", httpDefault(), "dashboard `address`; empty or \"off\" disables it (env ZAINVPN_HTTP)")
	flag.StringVar(&cfg.state, "state", envOr("ZAINVPN_STATE", "zainvpn-state.json"), "state `file` (env ZAINVPN_STATE)")
	// No env default here, so -help never prints the password.
	flag.StringVar(&cfg.adminPassword, "admin-password", "", "dashboard password (prefer env ZAINVPN_ADMIN_PASSWORD)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if cfg.adminPassword == "" {
		cfg.adminPassword = os.Getenv("ZAINVPN_ADMIN_PASSWORD")
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	if err := run(cfg, logger); err != nil {
		logger.Fatal(err)
	}
}

func run(cfg config, logger *log.Logger) error {
	srv, err := server.New(cfg.state, logger)
	if err != nil {
		return fmt.Errorf("load state %s: %w", cfg.state, err)
	}

	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	uaddr, err := net.ResolveUDPAddr("udp", cfg.listen)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return err
	}
	defer udp.Close()
	if err := udp.SetReadBuffer(udpBuffer); err != nil {
		logger.Printf("warning: UDP read buffer: %v", err)
	}
	if err := udp.SetWriteBuffer(udpBuffer); err != nil {
		logger.Printf("warning: UDP write buffer: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln, udp) }()
	logger.Printf("zainVPN coordinator %s on %s (TCP control, UDP relay), state %s", version, ln.Addr(), cfg.state)

	hs := startHTTP(cfg, srv, port, logger)

	select {
	case <-ctx.Done():
		logger.Printf("shutting down")
	case err = <-serveErr:
	}
	ln.Close()
	udp.Close()
	if hs != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}
	return err
}

// startHTTP starts the dashboard, or just /healthz when no admin password is
// set. A dashboard that can't start is logged but doesn't stop the VPN.
func startHTTP(cfg config, srv *server.Server, controlPort int, logger *log.Logger) *http.Server {
	if cfg.http == "" || cfg.http == "off" {
		logger.Printf("dashboard disabled (ZAINVPN_HTTP is %q)", cfg.http)
		return nil
	}
	var h http.Handler
	what := "dashboard on http://%s"
	if cfg.adminPassword == "" {
		logger.Printf("WARNING: ZAINVPN_ADMIN_PASSWORD is not set, so the admin dashboard is disabled. Set it and restart to enable it.")
		h = healthOnly()
		what = "health check on http://%s/healthz"
	} else {
		h = dashboard.New(srv, cfg.adminPassword, version, controlPort, logger)
	}

	ln, err := net.Listen("tcp", cfg.http)
	if err != nil {
		logger.Printf("ERROR: dashboard: %v (the VPN coordinator keeps running)", err)
		return nil
	}
	hs := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(logger.Writer(), "http: ", logger.Flags()),
	}
	go func() {
		if err := hs.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("ERROR: dashboard: %v", err)
		}
	}()
	logger.Printf(what, ln.Addr())
	return hs
}

func healthOnly() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "The zainVPN dashboard is disabled: set ZAINVPN_ADMIN_PASSWORD and restart the coordinator.", http.StatusServiceUnavailable)
	})
	return mux
}

// envOr returns the environment variable, or def when it is unset or empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// httpDefault honours an explicitly empty ZAINVPN_HTTP, which disables the dashboard.
func httpDefault() string {
	if v, ok := os.LookupEnv("ZAINVPN_HTTP"); ok {
		return v
	}
	return ":21958"
}
