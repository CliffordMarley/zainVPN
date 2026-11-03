package proto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

// Shared files are encrypted on the client with the network's key, so the
// coordinator only stores ciphertext. A file is
//
//	"ZVF1" [prefix:16] chunk...
//
// where each chunk is up to fileChunk bytes of plaintext sealed with nonce
// prefix||index and additional data "zvf1"||final. The last chunk is always
// shorter than a full one (possibly empty), so truncating, reordering or
// dropping chunks is detected.
const (
	fileChunk   = 64 << 10
	filePrefix  = 16
	fileTag     = 16
	fileHeader  = 4 + filePrefix
	sealedChunk = fileChunk + fileTag
)

var (
	fileMagic    = []byte("ZVF1")
	ErrBadFile   = errors.New("shared file is damaged or wasn't encrypted for this network")
	errShortName = errors.New("bad file name")
)

// Shared-files HTTP API (the coordinator's /share/v1/files): headers carrying
// a file's metadata on upload and download, and the JSON listing.
const (
	ShareHeaderName = "X-ZainVPN-Name" // Keys.SealName of the file name
	ShareHeaderSize = "X-ZainVPN-Size" // plaintext size in bytes
)

// ShareFile is one entry in a network's shared folder.
type ShareFile struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"` // sealed; only members can read it
	Size     int64     `json:"size"` // plaintext bytes, as declared by the uploader
	Stored   int64     `json:"stored"`
	By       string    `json:"by"` // uploader's nickname
	Device   string    `json:"device"`
	Uploaded time.Time `json:"uploaded"`
}

// ShareListing is a folder's files and limits.
type ShareListing struct {
	Files   []ShareFile `json:"files"`
	Used    int64       `json:"used"`
	Quota   int64       `json:"quota"`
	MaxFile int64       `json:"maxFile"`
}

// SealedSize is the encrypted size of n bytes of plaintext.
func SealedSize(n int64) int64 {
	return fileHeader + n + (n/fileChunk+1)*fileTag
}

func chunkNonce(prefix []byte, i uint64) []byte {
	n := make([]byte, NonceLen)
	copy(n, prefix)
	binary.BigEndian.PutUint64(n[filePrefix:], i)
	return n
}

func chunkAD(final bool) []byte {
	if final {
		return []byte("zvf1\x01")
	}
	return []byte("zvf1\x00")
}

// SealFile encrypts src to dst.
func (k *Keys) SealFile(dst io.Writer, src io.Reader) error {
	prefix := make([]byte, filePrefix)
	if _, err := rand.Read(prefix); err != nil {
		return err
	}
	if _, err := dst.Write(append(append([]byte{}, fileMagic...), prefix...)); err != nil {
		return err
	}
	buf := make([]byte, fileChunk, sealedChunk)
	for i := uint64(0); ; i++ {
		n, err := io.ReadFull(src, buf[:fileChunk])
		final := err == io.EOF || err == io.ErrUnexpectedEOF
		if err != nil && !final {
			return err
		}
		ct := k.aead.Seal(buf[:0], chunkNonce(prefix, i), buf[:n], chunkAD(final))
		if _, err := dst.Write(ct); err != nil {
			return err
		}
		if final {
			return nil
		}
	}
}

// OpenFile decrypts src (as written by SealFile) to dst. Plaintext is
// written chunk by chunk, so on an error dst may hold a partial file.
func (k *Keys) OpenFile(dst io.Writer, src io.Reader) error {
	hdr := make([]byte, fileHeader)
	if _, err := io.ReadFull(src, hdr); err != nil || string(hdr[:4]) != string(fileMagic) {
		return ErrBadFile
	}
	prefix := hdr[4:]
	buf := make([]byte, sealedChunk)
	for i := uint64(0); ; i++ {
		n, err := io.ReadFull(src, buf)
		final := err == io.EOF || err == io.ErrUnexpectedEOF
		if err != nil && !final {
			return err
		}
		pt, err := k.aead.Open(buf[:0], chunkNonce(prefix, i), buf[:n], chunkAD(final))
		if err != nil {
			return ErrBadFile
		}
		if _, err := dst.Write(pt); err != nil {
			return err
		}
		if final {
			return nil
		}
	}
}

// SealName encrypts a file name for the coordinator's file list.
func (k *Keys) SealName(name string) string {
	nonce := make([]byte, NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(k.aead.Seal(nonce, nonce, []byte(name), []byte("zvn1")))
}

// OpenName decrypts a name made by SealName.
func (k *Keys) OpenName(s string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) < NonceLen+fileTag {
		return "", errShortName
	}
	pt, err := k.aead.Open(nil, b[:NonceLen], b[NonceLen:], []byte("zvn1"))
	if err != nil {
		return "", errShortName
	}
	return string(pt), nil
}
