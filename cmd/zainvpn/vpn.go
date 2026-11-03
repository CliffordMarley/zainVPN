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
	"zainvpn/internal/proto"
)

// stateSetup is the Status state while this PC isn't in a network (no
// invite code yet). The engine never reports it.
const (
	stateSetup   = "setup"
	setupMessage = "Create or join a network to get started"
)

// adapter is the virtual adapter: the engine's Host, plus removing the
// address while no network is joined.
type adapter interface {
	client.Host
	ClearAddress() error
}

// vpn owns the engine: it runs one client.Engine at a time on the adapter and
// replaces it when the settings change. It is the UI's backend.
type vpn struct {
	log  *log.Logger
	ring *logRing
	path string // config.json

	updateMu sync.Mutex // serializes Update

	mu     sync.Mutex
	cfg    client.Config
	host   adapter // nil until the adapter is ready
	run    *engineRun
	phase  string // status message while there's no adapter yet
	engErr string // last engine failure, while waiting to restart it
	note   string // setup message after a bad saved invite, until the next change
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
		logger.Printf("no settings yet (%s); waiting for them in the zainVPN app", v.path)
	case err != nil:
		logger.Printf("load settings: %v", err)
	default:
		old := cfg
		ensureIdentity(&cfg)
		if err := cleanInvite(&cfg); err != nil {
			logger.Printf("ignoring the saved invite code: %v", err) // never log the code: it's the secret
			v.note = "The saved invite code isn't valid. Create or join a network to get started"
		}
		if cfg != old {
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

func (v *vpn) setHost(h adapter) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.host, v.phase = h, ""
	if v.cfg.Invite == "" {
		v.clearAddressLocked() // Windows may have kept the last network's address
	}
	if v.run == nil {
		v.startLocked()
	}
}

// clearAddressLocked removes the adapter's virtual address (best effort).
// It runs under mu, so no engine can be assigning one at the same time.
func (v *vpn) clearAddressLocked() {
	if v.host == nil {
		return
	}
	if err := v.host.ClearAddress(); err != nil {
		v.log.Printf("clear adapter address: %v", err)
	}
}

// startLocked starts an engine for v.cfg if the adapter is ready, a network
// is joined and the settings are complete. The engine is restarted if it
// ever fails.
func (v *vpn) startLocked() {
	cfg, host := v.cfg, v.host
	if v.closed || host == nil || cfg.Invite == "" || validateConfig(cfg) != nil {
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
// only ever start an engine with the new settings. Leaving a network also
// removes the adapter's address.
func (v *vpn) replace(c *client.Config) {
	v.mu.Lock()
	leaving := c != nil && c.Invite == "" && v.cfg.Invite != ""
	if c != nil {
		v.cfg, v.engErr, v.note = *c, "", ""
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
		if leaving {
			v.clearAddressLocked()
		}
		if v.run == nil {
			v.startLocked()
		}
		v.mu.Unlock()
	}
}

func (v *vpn) stop() { v.replace(nil) }

func (v *vpn) Status() client.Status {
	v.mu.Lock()
	cfg, host, phase, engErr, note := v.cfg, v.host, v.phase, v.engErr, v.note
	v.mu.Unlock()
	st := client.Status{
		State: client.StateStarting, Message: phase,
		Name: cfg.Name, Server: cfg.Server, Peers: []client.PeerStatus{},
	}
	switch e := v.eng.Load(); {
	case cfg.Invite == "":
		st.State, st.Message = stateSetup, setupMessage
		if note != "" {
			st.Message = note
		} else if checkServer(cfg.Server) != nil {
			st.Message = "Enter your coordinator address in Settings, then create or join a network"
		}
		return st
	case e != nil && engErr == "":
		st = e.Status()
	case engErr != "":
		st.State, st.Message = client.StateError, engErr
	case host != nil:
		if err := validateConfig(cfg); err != nil {
			st.State, st.Message = client.StateError, "Finish setting up zainVPN in Settings: "+err.Error()
		}
	}
	if st.Invite == "" { // the engine hasn't parsed it yet
		if inv, err := proto.ParseInvite(cfg.Invite); err == nil {
			st.Network, st.Invite = inv.Label, inv.String()
		}
	}
	return st
}

func (v *vpn) Config() client.Config {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.cfg
}

// Update changes the settings with fn, saves them and reconnects with them
// on the same adapter. If fn fails, nothing changes and its error is
// returned as is.
func (v *vpn) Update(fn func(*client.Config) error) error {
	v.updateMu.Lock()
	defer v.updateMu.Unlock()
	old := v.Config()
	c := old
	if err := fn(&c); err != nil {
		return err
	}
	if err := saveConfig(v.path, c); err != nil {
		return err
	}
	if c == old {
		return nil
	}
	network := "no network"
	if l := networkLabel(c.Invite); l != "" {
		network = fmt.Sprintf("network %q", l) // never the code: logs get shared
	}
	v.log.Printf("settings changed: %s, coordinator %s, nickname %q", network, c.Server, c.Name)
	v.replace(&c)
	return nil
}

func (v *vpn) Logs() []string { return v.ring.Lines() }
