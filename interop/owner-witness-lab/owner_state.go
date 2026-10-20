package ownerwitness

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
)

var headMagic = [8]byte{'A', 'K', 'O', 'W', 'N', '0', '1', 0}

const headFileSize = 8 + 16 + 16 + 8 + 32 + 32

// ReadOwnerHead reads a PRE-EXISTING head from the independently operated
// owner. It never provisions, truncates, repairs or advances it. SHA256 here
// detects damage, NOT a hostile rollback of the owner's own persistent store.
// A real deployment MUST provide OS custody and non-rollbackable owner state.
func ReadOwnerHead(path string) (Head, error) {
	var empty Head
	metadata, err := os.Lstat(path)
	if err != nil {
		return empty, err
	}
	if !metadata.Mode().IsRegular() || metadata.Size() != headFileSize {
		return empty, errors.New("wrong owner head object type or size")
	}
	f, err := os.Open(path)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	var frame [headFileSize]byte
	if _, err := io.ReadFull(f, frame[:]); err != nil {
		return empty, err
	}
	var extra [1]byte
	if n, err := f.Read(extra[:]); n != 0 || err != io.EOF {
		return empty, errors.New("owner head trailing bytes or read error")
	}
	if !bytes.Equal(frame[:8], headMagic[:]) {
		return empty, errors.New("bad owner head magic")
	}
	checksum := sha256.Sum256(frame[:headFileSize-32])
	if !bytes.Equal(checksum[:], frame[headFileSize-32:]) {
		return empty, errors.New("owner head checksum mismatch")
	}
	// Decode the same canonical fields, using an independent, never-zero nonce.
	var nonce [32]byte
	nonce[0] = 1
	payload := append([]byte(domain), frame[8:headFileSize-32]...)
	payload = append(payload, nonce[:]...)
	head, _, err := decode(payload)
	return head, err
}
