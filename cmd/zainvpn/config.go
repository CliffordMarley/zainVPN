//go:build windows

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/windows"

	"zainvpn/internal/client"
	"zainvpn/internal/proto"
)

const (
	serviceName = "zainVPN"
	adapterName = "zainVPN"
	uiAddr      = "127.0.0.1:7779"
	maxNameLen  = 32 // the coordinator truncates longer nicknames
)

// dataDir is %ProgramData%\zainVPN.
func dataDir() (string, error) {
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", fmt.Errorf("locate ProgramData: %w", err)
	}
	return filepath.Join(pd, "zainVPN"), nil
}

func configPath(dir string) string { return filepath.Join(dir, "config.json") }

// ensureDataDir creates the data dir and restricts it to SYSTEM and
// Administrators, since config.json holds the invite code (the network's
// secret). The dir is returned even when only the lock-down failed.
func ensureDataDir() (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, lockDown(dir)
}

// lockDown gives SYSTEM and Administrators full control of dir and removes
// inherited access (ProgramData lets every user read). SIDs are used rather
// than names, which are localized.
func lockDown(dir string) error {
	set := func(path, sddl string) error {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return err
		}
		dacl, _, err := sd.DACL()
		if err != nil {
			return err
		}
		if dacl == nil {
			return errors.New("empty DACL") // would mean full access for everyone
		}
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	}
	if err := set(dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"); err != nil {
		return fmt.Errorf("restrict access to %s: %w", dir, err)
	}
	// Files written before the lock-down (e.g. by the installer) may carry
	// their own explicit ACEs; replace them too.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !e.IsDir() {
			if err := set(filepath.Join(dir, e.Name()), "D:P(A;;FA;;;SY)(A;;FA;;;BA)"); err != nil {
				return fmt.Errorf("restrict access to %s: %w", e.Name(), err)
			}
		}
	}
	return nil
}

// loadConfig reads config.json, with or without a UTF-8 BOM (editors such
// as Notepad may add one). Fields of older versions ("network", "password")
// are ignored, so they're dropped on the next save.
func loadConfig(path string) (client.Config, error) {
	var c client.Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	c.Server = strings.TrimSpace(c.Server)
	c.Invite = strings.TrimSpace(c.Invite)
	c.Name = strings.TrimSpace(c.Name)
	return c, nil
}

// saveConfig writes config.json atomically.
func saveConfig(path string, c client.Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("save settings: %w", err)
	}
	return nil
}

// ensureIdentity fills in a device ID and nickname if missing and reports
// whether it changed c.
func ensureIdentity(c *client.Config) bool {
	changed := false
	if c.DeviceID == "" {
		var b [16]byte
		rand.Read(b[:])
		c.DeviceID = hex.EncodeToString(b[:])
		changed = true
	}
	if c.Name == "" {
		c.Name = computerName()
		changed = true
	}
	if n := truncate(c.Name, maxNameLen); n != c.Name {
		c.Name, changed = n, true
	}
	return changed
}

func computerName() string {
	if n, err := os.Hostname(); err == nil && n != "" {
		return truncate(n, maxNameLen)
	}
	return "player"
}

func truncate(s string, runes int) string {
	for utf8.RuneCountInString(s) > runes {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// validateConfig checks the settings. An empty invite is fine: this PC just
// isn't in a network yet.
func validateConfig(c client.Config) error {
	if err := checkServer(c.Server); err != nil {
		return err
	}
	if c.Invite != "" {
		if _, err := proto.ParseInvite(c.Invite); err != nil {
			return err
		}
	}
	return nil
}

// cleanInvite rewrites c.Invite in its normal form (label-XXXX-XXXX-XXXX).
// An invalid code is removed, since it could never connect, and reported.
func cleanInvite(c *client.Config) error {
	if c.Invite == "" {
		return nil
	}
	inv, err := proto.ParseInvite(c.Invite)
	if err != nil {
		c.Invite = ""
		return err
	}
	c.Invite = inv.String()
	return nil
}

// networkLabel is the name part of an invite code ("" if it isn't valid),
// for logs and messages. Never show the rest: it's the network's secret.
func networkLabel(invite string) string {
	inv, err := proto.ParseInvite(invite)
	if err != nil {
		return ""
	}
	return inv.Label
}

func checkName(name string) error {
	if utf8.RuneCountInString(name) > maxNameLen {
		return fmt.Errorf("nickname is too long (at most %d characters)", maxNameLen)
	}
	return nil
}

// checkServer accepts "host" or "host:port", the forms the engine dials.
func checkServer(s string) error {
	if s == "" {
		return errors.New("coordinator address is required")
	}
	host, port := s, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	}
	if host == "" || strings.Contains(s, "://") || strings.ContainsAny(host, " \t/\\@:?#") {
		return fmt.Errorf("coordinator address %q should be just a host name or IP address, optionally with :port, for example 203.0.113.10 or vpn.example.com:29814", s)
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("coordinator port %q is not valid", port)
		}
	}
	return nil
}
