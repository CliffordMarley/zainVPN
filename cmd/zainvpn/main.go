//go:build windows

// Command zainvpn is the zainVPN Windows client: a background service that
// puts this PC on a virtual LAN with friends, plus a small CLI to install and
// manage it. The dashboard lives at http://127.0.0.1:7779/.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"zainvpn/internal/client"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

var errUsage = errors.New("usage")

const usage = `zainVPN - virtual LAN for playing games with friends

Usage: zainvpn <command> [options]

Commands:
  install [--server S] [--invite CODE] [--name X]
              save settings, then install and start the background service (admin)
  stop        stop the background service (admin)
  uninstall   remove the service, firewall rule, adapter driver and settings (admin)
  run         run in the foreground for debugging; Ctrl+C stops (admin)
  status      show the connection status
  open        open the dashboard (http://127.0.0.1:7779/)
  ui-demo     preview the dashboard with fake data [--empty]
  version     print the version
`

func main() {
	if len(os.Args) < 2 {
		if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
			os.Exit(runService())
		}
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "install":
		err = cmdInstall(args)
	case "stop":
		err = cmdStop()
	case "uninstall":
		err = cmdUninstall()
	case "run":
		err = cmdRun()
	case "status":
		err = cmdStatus()
	case "open":
		err = cmdOpen()
	case "ui-demo":
		err = cmdUIDemo(args)
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "--help", "-h", "/?":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "zainvpn: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	switch {
	case errors.Is(err, errUsage):
		os.Exit(2) // the flag package already printed the problem
	case err != nil:
		fmt.Fprintf(os.Stderr, "zainvpn %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

// cmdRun runs the client in the foreground, logging to the console too.
func cmdRun() error {
	if !isElevated() {
		return errNotAdmin
	}
	if st, err := serviceState(); err == nil && st != svc.Stopped {
		return errors.New(`the zainVPN service is running; stop it first with "zainvpn stop"`)
	}
	dir, derr := ensureDataDir()
	if dir == "" {
		return derr
	}
	logger, ring, closeLog := setupLogging(dir, true)
	defer closeLog()
	if derr != nil {
		logger.Printf("data folder: %v", derr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	context.AfterFunc(ctx, stop) // a second Ctrl+C kills the process
	logger.Printf("zainVPN %s running in the foreground (Ctrl+C to stop)", version)
	err := runVPN(ctx, logger, ring, dir)
	logger.Printf("stopped")
	return err
}

func cmdStatus() error {
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + uiAddr + "/api/status")
	if err != nil {
		return errors.New("service not running")
	}
	defer resp.Body.Close()
	var s statusResponse
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&s) != nil {
		return fmt.Errorf("unexpected response from the dashboard (%s)", resp.Status)
	}
	st := s.Status
	state := map[string]string{client.StateOnline: "Connected", client.StateError: "Error", stateSetup: "Not in a network"}[st.State]
	if state == "" {
		state = "Connecting"
	}
	if st.Message != "" {
		state += " - " + st.Message
	}
	ip := st.IP
	if ip == "" {
		ip = "no address yet"
	}
	relay := "relay unavailable"
	if st.Relay {
		relay = "relay available"
	}
	online := 0
	for _, p := range st.Peers {
		if p.Online {
			online++
		}
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "zainVPN %s\n", s.Version)
	fmt.Fprintf(w, "Status:\t%s\n", state)
	fmt.Fprintf(w, "This PC:\t%s (%s)\n", st.Name, ip)
	if st.Network == "" {
		st.Network = "none"
	}
	fmt.Fprintf(w, "Network:\t%s\n", st.Network)
	if st.Invite != "" {
		fmt.Fprintf(w, "Invite code:\t%s\n", st.Invite)
	}
	fmt.Fprintf(w, "Coordinator:\t%s (%s)\n", st.Server, relay)
	fmt.Fprintf(w, "Players:\t%d of %d online\n", online, len(st.Peers))
	w.Flush()
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, p := range st.Peers {
		path, ping := map[string]string{"direct": "direct", "relay": "relayed"}[p.Path], ""
		if p.RTTms >= 0 && p.Online {
			ping = fmt.Sprintf("%.0f ms", p.RTTms)
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n", p.Name, p.IP, onlineWord(p.Online), path, ping)
	}
	w.Flush()
	return nil
}

func onlineWord(on bool) string {
	if on {
		return "online"
	}
	return "offline"
}

func cmdOpen() error {
	url := "http://" + uiAddr + "/"
	verb, _ := windows.UTF16PtrFromString("open")
	file, _ := windows.UTF16PtrFromString(url)
	if err := windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL); err != nil {
		return fmt.Errorf("open %s: %w", url, err)
	}
	if !uiReachable() {
		fmt.Fprintln(os.Stderr, "note: the zainVPN service doesn't seem to be running, so the page may not load")
	}
	return nil
}

func uiReachable() bool {
	c := http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://" + uiAddr + "/api/status")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
