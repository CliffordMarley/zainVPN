package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"zainvpn/internal/proto"
)

// ErrShareUnavailable means there's no shared folder to use right now.
var ErrShareUnavailable = errors.New("shared files are available once you're connected to a network")

// SharedFile is a file in the network's shared folder, with its name decrypted.
type SharedFile struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	By       string    `json:"by"`
	Mine     bool      `json:"mine"`
	Uploaded time.Time `json:"uploaded"`
}

// ShareListing is the folder's contents and limits.
type ShareListing struct {
	Files   []SharedFile `json:"files"`
	Used    int64        `json:"used"`
	Quota   int64        `json:"quota"`
	MaxFile int64        `json:"maxFile"`
}

// Share talks to the coordinator's shared folder for the current network.
type Share struct {
	base    string
	session string
	device  string
	keys    *proto.Keys
}

var shareClient = &http.Client{} // no timeout: transfers can be long; requests carry contexts

// Share returns a client for the network's shared folder while online.
func (e *Engine) Share() (*Share, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != StateOnline || !e.hasSess || e.sharePort == 0 || !e.serverUDP.IsValid() {
		return nil, ErrShareUnavailable
	}
	host := netip.AddrPortFrom(e.serverUDP.Addr(), uint16(e.sharePort))
	return &Share{
		base: "http://" + host.String() + "/share/v1/files", session: hex.EncodeToString(e.session[:]),
		device: e.cfg.DeviceID, keys: e.keys,
	}, nil
}

func (s *Share) request(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err == nil {
		req.Header.Set("Authorization", "Bearer "+s.session)
	}
	return req, err
}

func (s *Share) do(req *http.Request) (*http.Response, error) {
	resp, err := shareClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can't reach the coordinator's shared folder: %w", err)
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		var e struct{ Error string }
		json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return nil, errors.New(e.Error)
	}
	return resp, nil
}

// List returns the folder's files, newest first.
func (s *Share) List(ctx context.Context) (ShareListing, error) {
	var l ShareListing
	req, err := s.request(ctx, http.MethodGet, s.base, nil)
	if err != nil {
		return l, err
	}
	resp, err := s.do(req)
	if err != nil {
		return l, err
	}
	defer resp.Body.Close()
	var raw proto.ShareListing
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return l, err
	}
	l = ShareListing{Files: []SharedFile{}, Used: raw.Used, Quota: raw.Quota, MaxFile: raw.MaxFile}
	for _, f := range raw.Files {
		name, err := s.keys.OpenName(f.Name)
		if err != nil {
			continue // not encrypted for this network's key
		}
		l.Files = append(l.Files, SharedFile{ID: f.ID, Name: name, Size: f.Size, By: f.By, Mine: f.Device == s.device, Uploaded: f.Uploaded})
	}
	return l, nil
}

// Upload encrypts size bytes from r and stores them as name.
func (s *Share) Upload(ctx context.Context, name string, size int64, r io.Reader) error {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(s.keys.SealFile(pw, io.LimitReader(r, size))) }()
	req, err := s.request(ctx, http.MethodPut, s.base, pr)
	if err != nil {
		pr.Close()
		return err
	}
	req.ContentLength = proto.SealedSize(size)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(proto.ShareHeaderName, s.keys.SealName(name))
	req.Header.Set(proto.ShareHeaderSize, strconv.FormatInt(size, 10))
	resp, err := s.do(req)
	pr.Close()
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Download fetches a file. Call write to stream the decrypted contents.
func (s *Share) Download(ctx context.Context, id string) (name string, size int64, write func(io.Writer) error, err error) {
	req, err := s.request(ctx, http.MethodGet, s.base+"/"+id, nil)
	if err != nil {
		return "", 0, nil, err
	}
	resp, err := s.do(req)
	if err != nil {
		return "", 0, nil, err
	}
	name, err = s.keys.OpenName(resp.Header.Get(proto.ShareHeaderName))
	if err != nil {
		resp.Body.Close()
		return "", 0, nil, proto.ErrBadFile
	}
	size, _ = strconv.ParseInt(resp.Header.Get(proto.ShareHeaderSize), 10, 64)
	return name, size, func(w io.Writer) error {
		defer resp.Body.Close()
		return s.keys.OpenFile(w, resp.Body)
	}, nil
}

// Delete removes a file this device uploaded.
func (s *Share) Delete(ctx context.Context, id string) error {
	req, err := s.request(ctx, http.MethodDelete, s.base+"/"+id, nil)
	if err != nil {
		return err
	}
	resp, err := s.do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
