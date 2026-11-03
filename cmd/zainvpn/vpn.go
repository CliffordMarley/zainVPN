//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"zainvpn/internal/client"
)

// vpn owns the engine: it runs one client.Engine at a time on the adapter and
// replaces it when the settings change. It is the UI's backend.
type vpn struct {
	log  *log.Logger
	ring *logRing
	path string // config.json

	applyMu sync.Mutex // serializes Apply

	mu     sync.Mutex
	cfg    client.Config
	host   client.Host // nil until the adapter is ready
	run    *engineRun
	phase  string // status message while there's no adapter yet
	engErr string // last engine failure, while waiting to restart it
	closed bool

	eng atomic.Pointer[client.Engine] // current engine, for the packet path
}

type engineRun struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// runVPN is the client runtime shared by the service and "run": it brings up
// the adapter, the engine and the local UI, and tears them down when ctx is
// cancelled. It returns an error if the adapter fails.
func runVPN(ctx context.Context, logger *log.Logger, ring *logRing, dir string) error {
	v := &vpn{log: logger, ring: ring, path: configPath(dir), phase: "Setting up the zainVPN network adapter…"}
	cfg, err := loadConfig(v.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		logger.Printf("no settings yet (%s); waiting for them in the dashboard", v.path)
	case err != nil:
		logger.Printf("load settings: %v", err)
	default:
		if ensureIdentity(&cfg) {
			if err := saveConfig(v.path, cfg); err != nil {
				logger.Print(err)
			}
		}
	}
	v.cfg = cfg

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	uiDone := make(chan struct{})
	go func() {
		defer close(uiDone)
		serveUI(ctx, v, logger)
	}()

	dev, err := openAdapter(ctx, logger)
	if err != nil {
		cancel()
		<-uiDone
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	host := newAdapterHost(ctx, dev, logger)
	readDone := make(chan error, 1)
	go func() { readDone <- readTUN(dev, &v.eng) }()
	logger.Printf("adapter %q ready", adapterName)
	v.setHost(host)

	var fatal error
	select {
	case <-ctx.Done():
	case err := <-readDone:
		if err == nil {
			err = errors.New("closed unexpectedly")
		}
		fatal = fmt.Errorf("network adapter: %w", err)
		readDone = nil
	}
	v.stop()
	cancel()
	<-uiDone
	dev.Close() // removes the adapter
	if readDone != nil {
		<-readDone
	}
	return fatal
}

func (v *vpn) setHost(h client.Host) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.host, v.phase = h, ""
	if v.run == nil {
		v.startLocked()
	}
}

// startLocked starts an engine for v.cfg if the adapter is ready and the
// settings are complete. The engine is restarted if it ever fails.
func (v *vpn) startLocked() {
	cfg, host := v.cfg, v.host
	if v.closed || host == nil || validateConfig(cfg) != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &engineRun{cancel: cancel, done: make(chan struct{})}
	v.run, v.engErr = r, ""
	go func() {
		defer close(r.done)
		for {
			e := client.New(cfg, host, v.log)
			v.eng.Store(e)
			v.setEngErr("")
			err := e.Run(ctx)
			v.eng.CompareAndSwap(e, nil)
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				err = errors.New("stopped unexpectedly")
			}
			v.log.Printf("engine: %v (restarting in 5s)", err)
			v.setEngErr(err.Error())
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
}

func (v *vpn) setEngErr(msg string) {
	v.mu.Lock()
	v.engErr = msg
	v.mu.Unlock()
}

// replace swaps in new settings (if c is non-nil) or shuts down for good,
// stopping the running engine and waiting for it. The settings change under
// the same lock that detaches the old engine, so a concurrent setHost can
// only ever start an engine with the new settings.
func (v *vpn) replace(c *client.Config) {
	v.mu.Lock()
	if c != nil {
		v.cfg, v.engErr = *c, ""
	} else {
		v.closed = true
	}
	r := v.run
	v.run = nil
	v.mu.Unlock()
	if r != nil {
		r.cancel()
		<-r.done
	}
	if c != nil {
		v.mu.Lock()
		if v.run == nil {
			v.startLocked()
		}
		v.mu.Unlock()
	}
}

func (v *vpn) stop() { v.replace(nil) }

func (v *vpn) Status() client.Status {
	v.mu.Lock()
	cfg, host, phase, engErr := v.cfg, v.host, v.phase, v.engErr
	v.mu.Unlock()
	if e := v.eng.Load(); e != nil && engErr == "" {
		return e.Status()
	}
	st := client.Status{
		State: client.StateStarting, Message: phase,
		Name: cfg.Name, Network: cfg.Network, Server: cfg.Server, Peers: []client.PeerStatus{},
	}
	if engErr != "" {
		st.State, st.Message = client.StateError, engErr
	} else if err := validateConfig(cfg); host != nil && err != nil {
		st.State, st.Message = client.StateError, "Finish setting up zainVPN in Settings: "+err.Error()
	}
	return st
}

func (v *vpn) Config() client.Config {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.cfg
}

// Apply saves new settings and reconnects with them on the same adapter.
func (v *vpn) Apply(c client.Config) error {
	v.applyMu.Lock()
	defer v.applyMu.Unlock()
	if err := saveConfig(v.path, c); err != nil {
		return err
	}
	v.log.Printf("settings changed: network %q, coordinator %s, nickname %q", c.Network, c.Server, c.Name)
	v.replace(&c)
	return nil
}

func (v *vpn) Logs() []string { return v.ring.Lines() }
