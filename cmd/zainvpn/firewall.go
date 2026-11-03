//go:build windows

package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"

	"zainvpn/internal/proto"
)

const firewallRule = "zainVPN"

// systemTool returns the full path of a tool in System32, so a planted
// netsh.exe in the working directory or PATH is never run elevated.
func systemTool(rel string) string {
	if dir, err := windows.GetSystemDirectory(); err == nil {
		return filepath.Join(dir, rel)
	}
	return rel
}

// runHidden runs exe with a literal command-line tail and no console window.
func runHidden(ctx context.Context, exe, args string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
		CmdLine:       syscall.EscapeArg(exe) + " " + args,
	}
	out, err := cmd.CombinedOutput()
	return bytes.TrimSpace(out), err
}

// addFirewallRules allows inbound traffic from the virtual LAN (so friends
// can join games hosted here) and inbound UDP to zainvpn.exe (so peers can
// punch a direct path even when their NAT changes ports). Both rules share
// one name, so a single delete removes them.
func addFirewallRules(exe string) error {
	removeFirewallRules()
	netsh := systemTool("netsh.exe")
	rules := []string{
		fmt.Sprintf(`advfirewall firewall add rule name="%s" dir=in action=allow remoteip=%s profile=any enable=yes`, firewallRule, proto.Subnet),
		fmt.Sprintf(`advfirewall firewall add rule name="%s" dir=in action=allow program="%s" protocol=UDP profile=any enable=yes`, firewallRule, exe),
	}
	for _, r := range rules {
		if out, err := runHidden(context.Background(), netsh, r); err != nil {
			return fmt.Errorf("add firewall rule: %v: %s", err, out)
		}
	}
	return nil
}

func removeFirewallRules() {
	runHidden(context.Background(), systemTool("netsh.exe"),
		fmt.Sprintf(`advfirewall firewall delete rule name="%s"`, firewallRule))
}
