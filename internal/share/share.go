// Package share is the coordinator's shared-files service: each network has
// a folder that its online members can upload to and download from. Clients
// encrypt files and names with the network key before uploading, so this
// service only ever stores ciphertext.
package share

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"zainvpn/internal/proto"
	"zainvpn/internal/server"
)

const transferTime = 6 * time.Hour // per-request deadline for big files

var idRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Store keeps files under dir/<network ID>/.
type Store struct {
	dir     string
	srv     *server.Server
	quota   int64 // per network, stored bytes
	maxFile int64 // plaintext bytes
	log     *log.Logger

	mu       sync.Mutex       // guards every index.json and reserved
	reserved map[string]int64 // bytes of uploads in progress, by network
}

func New(dir string, srv *server.Server, quota, maxFile int64, logger *log.Logger) *Store {
	return &Store{dir: dir, srv: srv, quota: quota, maxFile: maxFile, log: logger, reserved: map[string]int64{}}
}

// Handler serves /share/v1/. Every request needs "Authorization: Bearer
// <session>" from an online device's welcome message.
func (st *Store) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /share/v1/files", st.auth(st.list))
	m.HandleFunc("PUT /share/v1/files", st.auth(st.upload))
	m.HandleFunc("GET /share/v1/files/{id}", st.auth(st.download))
	m.HandleFunc("DELETE /share/v1/files/{id}", st.auth(st.remove))
	return m
}

type handler func(w http.ResponseWriter, r *http.Request, m server.Member)

func (st *Store) auth(next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		m, found := st.srv.MemberBySession(sess)
		if !ok || !found {
			httpError(w, http.StatusUnauthorized, "not connected to a network")
			return
		}
		// Invite-code networks have hex IDs, which are also safe folder names.
		if !idRE.MatchString(m.Network) {
			httpError(w, http.StatusForbidden, "shared files need a network joined with an invite code")
			return
		}
		next(w, r, m)
	}
}

func (st *Store) netDir(network string) string { return filepath.Join(st.dir, network) }

func (st *Store) readIndex(network string) ([]proto.ShareFile, error) {
	b, err := os.ReadFile(filepath.Join(st.netDir(network), "index.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var files []proto.ShareFile
	return files, json.Unmarshal(b, &files)
}

func (st *Store) writeIndex(network string, files []proto.ShareFile) error {
	b, err := json.MarshalIndent(files, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(st.netDir(network), "index.json")
	if err := os.WriteFile(p+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

func (st *Store) list(w http.ResponseWriter, r *http.Request, m server.Member) {
	st.mu.Lock()
	files, err := st.readIndex(m.Network)
	st.mu.Unlock()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	l := proto.ShareListing{Files: files, Quota: st.quota, MaxFile: st.maxFile}
	if l.Files == nil {
		l.Files = []proto.ShareFile{}
	}
	for _, f := range files {
		l.Used += f.Stored
	}
	sort.Slice(l.Files, func(i, j int) bool { return l.Files[i].Uploaded.After(l.Files[j].Uploaded) })
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(l)
}

func (st *Store) upload(w http.ResponseWriter, r *http.Request, m server.Member) {
	name := r.Header.Get(proto.ShareHeaderName)
	size, err := strconv.ParseInt(r.Header.Get(proto.ShareHeaderSize), 10, 64)
	switch {
	case name == "" || len(name) > 2048:
		httpError(w, http.StatusBadRequest, "missing file name")
		return
	case err != nil || size < 0:
		httpError(w, http.StatusBadRequest, "missing file size")
		return
	case size > st.maxFile:
		httpError(w, http.StatusRequestEntityTooLarge, "file is larger than this server allows ("+mb(st.maxFile)+")")
		return
	case r.ContentLength != proto.SealedSize(size):
		httpError(w, http.StatusBadRequest, "size doesn't match the upload")
		return
	}
	stored := r.ContentLength

	// Space is reserved while receiving, so parallel uploads can't overfill.
	var idb [16]byte
	rand.Read(idb[:])
	f := proto.ShareFile{ID: hex.EncodeToString(idb[:]), Name: name, Size: size, Stored: stored, By: m.Name, Device: m.Device}
	st.mu.Lock()
	files, err := st.readIndex(m.Network)
	used := st.reserved[m.Network]
	for _, x := range files {
		used += x.Stored
	}
	if err == nil && used+stored > st.quota {
		st.mu.Unlock()
		httpError(w, http.StatusInsufficientStorage, "the shared folder is full ("+mb(used)+" of "+mb(st.quota)+" used); delete something first")
		return
	}
	if err == nil {
		err = os.MkdirAll(st.netDir(m.Network), 0o700)
	}
	if err == nil {
		st.reserved[m.Network] += stored
	}
	st.mu.Unlock()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer func() {
		st.mu.Lock()
		if st.reserved[m.Network] -= stored; st.reserved[m.Network] <= 0 {
			delete(st.reserved, m.Network)
		}
		st.mu.Unlock()
	}()

	http.NewResponseController(w).SetReadDeadline(time.Now().Add(transferTime))
	path := filepath.Join(st.netDir(m.Network), f.ID+".bin")
	out, err := os.OpenFile(path+".part", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		var n int64
		n, err = io.Copy(out, http.MaxBytesReader(w, r.Body, stored))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err == nil && n != stored {
			err = io.ErrUnexpectedEOF
		}
	}
	if err == nil {
		err = os.Rename(path+".part", path)
	}
	if err != nil {
		os.Remove(path + ".part")
		httpError(w, http.StatusBadRequest, "upload failed: "+err.Error())
		return
	}

	st.mu.Lock()
	files, err = st.readIndex(m.Network)
	if err == nil {
		f.Uploaded = time.Now().UTC()
		err = st.writeIndex(m.Network, append(files, f))
	}
	st.mu.Unlock()
	if err != nil {
		os.Remove(path)
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	st.log.Printf("share: %s uploaded %s (%s) to network %s", m.Name, f.ID, mb(size), m.Network)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(f)
}

func (st *Store) find(network, id string) (proto.ShareFile, bool) {
	if !idRE.MatchString(id) {
		return proto.ShareFile{}, false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	files, _ := st.readIndex(network)
	for _, f := range files {
		if f.ID == id {
			return f, true
		}
	}
	return proto.ShareFile{}, false
}

func (st *Store) download(w http.ResponseWriter, r *http.Request, m server.Member) {
	f, ok := st.find(m.Network, r.PathValue("id"))
	if !ok {
		httpError(w, http.StatusNotFound, "file not found")
		return
	}
	in, err := os.Open(filepath.Join(st.netDir(m.Network), f.ID+".bin"))
	if err != nil {
		httpError(w, http.StatusNotFound, "file not found")
		return
	}
	defer in.Close()
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(transferTime))
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", strconv.FormatInt(f.Stored, 10))
	h.Set(proto.ShareHeaderName, f.Name)
	h.Set(proto.ShareHeaderSize, strconv.FormatInt(f.Size, 10))
	io.Copy(w, in)
}

func (st *Store) remove(w http.ResponseWriter, r *http.Request, m server.Member) {
	id := r.PathValue("id")
	st.mu.Lock()
	files, err := st.readIndex(m.Network)
	i := -1
	for j, f := range files {
		if f.ID == id {
			i = j
		}
	}
	switch {
	case err != nil:
	case i < 0:
		st.mu.Unlock()
		httpError(w, http.StatusNotFound, "file not found")
		return
	case files[i].Device != m.Device:
		st.mu.Unlock()
		httpError(w, http.StatusForbidden, "only "+files[i].By+" can delete this file")
		return
	default:
		err = st.writeIndex(m.Network, append(files[:i:i], files[i+1:]...))
	}
	st.mu.Unlock()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	os.Remove(filepath.Join(st.netDir(m.Network), id+".bin"))
	w.WriteHeader(http.StatusNoContent)
}

// RemoveNetwork deletes a network's whole folder (server.OnNetworkDeleted).
func (st *Store) RemoveNetwork(network string) {
	if !idRE.MatchString(network) {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := os.RemoveAll(st.netDir(network)); err != nil {
		st.log.Printf("share: remove %s: %v", network, err)
	}
}

func mb(n int64) string {
	if n >= 1<<30 {
		return strconv.FormatFloat(float64(n)/(1<<30), 'f', 1, 64) + " GB"
	}
	return strconv.FormatInt((n+(1<<20)-1)>>20, 10) + " MB"
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
