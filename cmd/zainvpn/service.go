//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wintun"
)

const svcTimeout = 20 * time.Second

var errNotAdmin = errors.New(`this command needs administrator rights: open a terminal with "Run as administrator" and try again`)

func isElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// service is the SCM handler.
type service struct{}

func (service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	dir, derr := ensureDataDir()
	logger, ring, closeLog := setupLogging(dir, false)
	defer closeLog()
	logger.Printf("zainVPN %s starting", version)
	if derr != nil {
		logger.Printf("data folder: %v", derr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runVPN(ctx, logger, ring, dir) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case err := <-done:
			// The runtime only returns on its own when it failed; a non-zero
			// exit code makes the SCM restart us (see installService).
			if err == nil {
				err = errors.New("stopped unexpectedly")
			}
			logger.Printf("fatal: %v", err)
			status <- svc.Status{State: svc.StopPending}
			return true, 1
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				logger.Printf("stopping")
				status <- svc.Status{State: svc.StopPending, WaitHint: 12000}
				cancel()
				select {
				case <-done:
					logger.Printf("stopped")
				case <-time.After(10 * time.Second):
					logger.Printf("cleanup timed out; exiting anyway")
				}
				return false, 0
			}
		}
	}
}

func runService() int {
	if err := svc.Run(serviceName, service{}); err != nil {
		return 1
	}
	return 0
}

// openService opens the zainVPN service with only the given access rights,
// so querying it works without elevation.
func openService(access uint32) (*mgr.Service, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(serviceName)
	h, err := windows.OpenService(scm, name, access)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: serviceName, Handle: h}, nil
}

// serviceState reports the service's state; ERROR_SERVICE_DOES_NOT_EXIST if
// it isn't installed.
func serviceState() (svc.State, error) {
	s, err := openService(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	st, err := s.Query()
	return st.State, err
}

// stopService asks the service to stop and waits for it, killing the
// process as a last resort so an upgrade can replace the files.
func stopService(s *mgr.Service) error {
	deadline := time.Now().Add(svcTimeout)
	sent := false
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		if !sent && st.State != svc.StopPending {
			_, err := s.Control(svc.Stop)
			switch {
			case err == nil, errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE):
				sent = true
			case errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL):
				// still starting; try again
			default:
				return fmt.Errorf("stop service: %w", err)
			}
		}
		if time.Now().After(deadline) {
			if st.ProcessId != 0 {
				if p, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, st.ProcessId); err == nil {
					err = windows.TerminateProcess(p, 1)
					windows.CloseHandle(p)
					if err == nil {
						time.Sleep(2 * time.Second)
						return nil
					}
				}
			}
			return fmt.Errorf("service did not stop within %s", svcTimeout)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func waitRunning(s *mgr.Service) error {
	deadline := time.Now().Add(svcTimeout)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		switch st.State {
		case svc.Running:
			return nil
		case svc.Stopped:
			code := st.Win32ExitCode
			if code == uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) {
				code = st.ServiceSpecificExitCode
			}
			return fmt.Errorf("service stopped right after starting (exit code %d); see the log in %%ProgramData%%\\zainVPN", code)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("service did not start within %s", svcTimeout)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func cmdInstall(args []string) error {
	fl := flag.NewFlagSet("install", flag.ContinueOnError)
	server := fl.String("server", "", "coordinator address (host or host:port)")
	invite := fl.String("invite", "", "invite code of a network to join (default: none; create or join one in the app)")
	name := fl.String("name", "", "nickname shown to friends (default: computer name)")
	if err := fl.Parse(args); err != nil {
		return errUsage
	}
	if fl.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fl.Arg(0))
	}
	if !isElevated() {
		return errNotAdmin
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	dir, err := ensureDataDir()
	if err != nil {
		return err
	}
	path := configPath(dir)
	cfg, err := loadConfig(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read settings: %w", err)
	}
	fl.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "server":
			cfg.Server = strings.TrimSpace(*server)
		case "invite":
			cfg.Invite = strings.TrimSpace(*invite)
		case "name":
			cfg.Name = strings.TrimSpace(*name)
		}
	})
	ensureIdentity(&cfg) // also trims an over-long nickname, as the coordinator would
	// Bad or missing settings don't stop the install (a silent install may
	// leave fields empty): they can be fixed in the app afterwards.
	if err := cleanInvite(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: ignoring the invite code: %v\n", err)
	}
	incomplete := validateConfig(cfg)
	if err := saveConfig(path, cfg); err != nil {
		return err
	}
	if err := addFirewallRules(exe); err != nil {
		return err
	}
	if err := installService(exe); err != nil {
		return err
	}
	switch label := networkLabel(cfg.Invite); {
	case incomplete != nil:
		fmt.Fprintf(os.Stderr, "warning: %v (pass --server, or set it in the zainVPN app)\n", incomplete)
		fmt.Printf("zainVPN is installed and running, but not connected yet.\nFinish setting it up at http://%s/\n", uiAddr)
	case label == "":
		fmt.Printf("zainVPN is installed and running as %q.\nCreate or join a network at http://%s/\n", cfg.Name, uiAddr)
	default:
		fmt.Printf("zainVPN is installed and running as %q on network %q.\nDashboard: http://%s/\n", cfg.Name, label, uiAddr)
	}
	return nil
}

// installService creates or updates the service, then (re)starts it so it
// picks up the current binary and settings.
func installService(exe string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	conf := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "zainVPN",
		Description:  "Virtual LAN for playing games with friends",
		Dependencies: []string{"Nsi", "TcpIp"},
	}
	s, err := m.OpenService(serviceName)
	if err == nil {
		old, err := s.Config()
		if err != nil {
			s.Close()
			return fmt.Errorf("read service config: %w", err)
		}
		conf.ServiceStartName, conf.SidType = old.ServiceStartName, old.SidType
		conf.BinaryPathName = `"` + exe + `"`
		if err := s.UpdateConfig(conf); err != nil {
			s.Close()
			return fmt.Errorf("update service: %w", err)
		}
	} else {
		s, err = m.CreateService(serviceName, exe, conf)
		if errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return errors.New("the old zainVPN service is still being removed; close the Services window (if open), wait a moment and try again")
		}
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
	}
	defer s.Close()

	restart := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	if err := s.SetRecoveryActions(restart, 24*60*60); err != nil {
		return fmt.Errorf("set service recovery: %w", err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("set service recovery: %w", err)
	}

	if err := stopService(s); err != nil {
		return err
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return waitRunning(s)
}

func cmdStop() error {
	s, err := openService(windows.SERVICE_STOP | windows.SERVICE_QUERY_STATUS)
	switch {
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST):
		fmt.Println("zainVPN service is not installed")
		return nil
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return errNotAdmin
	case err != nil:
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()
	if err := stopService(s); err != nil {
		return err
	}
	fmt.Println("zainVPN service stopped")
	return nil
}

// cmdUninstall removes everything install created. Parts that are already
// gone are skipped; only a service that exists but can't be removed fails.
func cmdUninstall() error {
	if !isElevated() {
		return errNotAdmin
	}
	warn := func(format string, a ...any) { fmt.Fprintf(os.Stderr, "warning: "+format+"\n", a...) }

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	s, err := m.OpenService(serviceName)
	if err == nil {
		err = stopService(s)
		if err == nil {
			if err = s.Delete(); errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
				err = nil
			}
		}
		s.Close()
	} else if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		err = nil
	}
	m.Disconnect()
	if err != nil {
		return fmt.Errorf("remove service: %w", err)
	}

	removeFirewallRules()
	if err := wintun.Uninstall(); err != nil {
		warn("remove Wintun driver: %v", err) // fine if it's in use by another app
	}
	if dir, err := dataDir(); err == nil {
		if err := os.RemoveAll(dir); err != nil {
			warn("remove %s: %v", dir, err)
		}
	}
	fmt.Println("zainVPN uninstalled")
	return nil
}
