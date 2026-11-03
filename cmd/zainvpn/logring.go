//go:build windows

package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	ringLines  = 300
	maxLogSize = 5 << 20
)

// logRing keeps the last lines written to the log, for the UI.
type logRing struct {
	mu    sync.Mutex
	lines []string
}

func (r *logRing) Write(p []byte) (int, error) {
	s := strings.TrimRight(string(p), "\r\n")
	r.mu.Lock()
	r.lines = append(r.lines, strings.Split(s, "\n")...)
	if len(r.lines) > 2*ringLines {
		r.lines = append([]string(nil), r.lines[len(r.lines)-ringLines:]...)
	}
	r.mu.Unlock()
	return len(p), nil
}

func (r *logRing) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.lines[max(0, len(r.lines)-ringLines):]...)
}

// logFile appends to zainvpn.log, moving it to zainvpn.log.old once it
// grows past maxLogSize (checked at startup and while running).
type logFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func openLogFile(path string) (*logFile, error) {
	l := &logFile{path: path}
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxLogSize {
		os.Rename(path, path+".old")
	}
	return l, l.open()
}

func (l *logFile) open() error {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	l.f, l.size = f, 0
	if fi, err := f.Stat(); err == nil {
		l.size = fi.Size()
	}
	return nil
}

func (l *logFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil && l.size > maxLogSize {
		l.f.Close()
		l.f = nil
		os.Rename(l.path, l.path+".old")
		l.open()
	}
	if l.f == nil {
		return len(p), nil
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

func (l *logFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// tee writes to every writer, ignoring errors (unlike io.MultiWriter, a
// failing log file doesn't starve the others).
type tee []io.Writer

func (t tee) Write(p []byte) (int, error) {
	for _, w := range t {
		w.Write(p)
	}
	return len(p), nil
}

// setupLogging points the standard logger (which wintun also uses) at the
// log file in dir, the in-memory ring and optionally stderr.
func setupLogging(dir string, console bool) (*log.Logger, *logRing, func()) {
	ring := &logRing{}
	w := tee{ring}
	if console {
		w = append(w, os.Stderr)
	}
	var lf *logFile
	var ferr error
	if dir != "" {
		if lf, ferr = openLogFile(filepath.Join(dir, "zainvpn.log")); ferr == nil {
			w = append(w, lf)
		}
	}
	log.SetOutput(w)
	log.SetFlags(log.LstdFlags)
	logger := log.Default()
	if ferr != nil {
		logger.Printf("open log file: %v", ferr)
	}
	return logger, ring, func() {
		if lf != nil {
			lf.Close()
		}
	}
}
