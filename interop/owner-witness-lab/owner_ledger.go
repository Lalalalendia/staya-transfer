package ownerwitness

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
)

// This is an experimental, DENY-only, pre-existing owner-side append log.
// SHA-256 detects damage, never authenticates storage or defeats a valid old
// snapshot replay. The trusted owner filesystem and a nonrollbackable anchor
// are future independent prerequisites, NOT implemented by this module.
const (
	ledgerHeaderSize = 48
	ledgerRecordSize = 112
	maxLedgerRecords = 4096
	maxLedgerBytes   = ledgerHeaderSize + ledgerRecordSize*maxLedgerRecords
	ledgerDenyOpcode = 1
)

var ledgerMagic = [8]byte{'A', 'K', 'O', 'L', 'G', '0', '1', 0}
var (
	ErrLedgerHold      = errors.New("owner ledger HOLD: absent, damaged, replaced or untrusted file")
	ErrLedgerStaleCAS  = errors.New("owner ledger HOLD: stale compare-and-swap epoch or floor")
	ErrLedgerExhausted = errors.New("owner ledger HOLD: capacity or monotonic floor exhausted")
)

type ledgerState struct {
	head     Head
	floors   map[[16]byte]uint64
	previous [32]byte
	size     int64
}

func ledgerHeader(installation, vault [16]byte) [ledgerHeaderSize]byte {
	var b [ledgerHeaderSize]byte
	copy(b[:8], ledgerMagic[:])
	copy(b[8:24], installation[:])
	copy(b[24:40], vault[:])
	return b
}

func ledgerRecordHash(data []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("AKULA_OWNER_LEDGER_RECORD_V1\x00"))
	_, _ = h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func parseLedger(f *os.File, installation, vault [16]byte) (ledgerState, error) {
	var s ledgerState
	if installation == [16]byte{} || vault == [16]byte{} {
		return s, ErrLedgerHold
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < ledgerHeaderSize || info.Size() > maxLedgerBytes {
		return s, ErrLedgerHold
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return s, ErrLedgerHold
	}
	buf, err := io.ReadAll(io.LimitReader(f, int64(maxLedgerBytes+1)))
	if err != nil || int64(len(buf)) != info.Size() || len(buf) < ledgerHeaderSize || len(buf) > maxLedgerBytes ||
		(len(buf)-ledgerHeaderSize)%ledgerRecordSize != 0 {
		return s, ErrLedgerHold
	}
	expected := ledgerHeader(installation, vault)
	if !bytes.Equal(buf[:ledgerHeaderSize], expected[:]) {
		return s, ErrLedgerHold
	}
	s.floors = make(map[[16]byte]uint64)
	s.previous = sha256.Sum256(buf[:ledgerHeaderSize])
	for offset := ledgerHeaderSize; offset < len(buf); offset += ledgerRecordSize {
		row := buf[offset : offset+ledgerRecordSize]
		next := s.head.Epoch + 1
		var replica [16]byte
		copy(replica[:], row[8:24])
		oldFloor := binary.LittleEndian.Uint64(row[24:32])
		newFloor := binary.LittleEndian.Uint64(row[32:40])
		current := s.floors[replica]
		rowHash := ledgerRecordHash(row[:80])
		if next == 0 || binary.LittleEndian.Uint64(row[:8]) != next || replica == [16]byte{} ||
			oldFloor != current || current == math.MaxUint64 || newFloor != current+1 ||
			!bytes.Equal(row[40:72], s.previous[:]) || row[72] != ledgerDenyOpcode ||
			!bytes.Equal(row[73:80], make([]byte, 7)) || !bytes.Equal(row[80:112], rowHash[:]) {
			return ledgerState{}, ErrLedgerHold
		}
		s.head.Epoch = next
		s.floors[replica] = newFloor
		s.previous = rowHash
	}
	all := make([]Floor, 0, len(s.floors))
	for replica, floor := range s.floors {
		all = append(all, Floor{Replica: replica, Epoch: floor})
	}
	digest, err := CanonicalDenyDigest(all)
	if err != nil {
		return ledgerState{}, ErrLedgerHold
	}
	s.head.Installation = installation
	s.head.Vault = vault
	s.head.DenyDigest = digest
	s.size = int64(len(buf))
	return s, nil
}

// openPinnedLedger refuses missing/symlink/nonregular files before opening,
// and compares path identity with the already-open handle AFTER taking the
// OS lock. Filesystem ancestor custody is NOT provided by this check.
func openPinnedLedger(path string) (*os.File, func(), error) {
	prior, err := os.Lstat(path)
	if err != nil || !prior.Mode().IsRegular() {
		return nil, nil, ErrLedgerHold
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0) // MUST NOT create/repair/truncate.
	if err != nil {
		return nil, nil, ErrLedgerHold
	}
	held, err := lockLedger(f)
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%w: exclusive lock unavailable: %v", ErrLedgerHold, err)
	}
	cleanup := func() { held(); _ = f.Close() }
	after, err := os.Lstat(path)
	onHandle, e2 := f.Stat()
	if err != nil || e2 != nil || !after.Mode().IsRegular() || !onHandle.Mode().IsRegular() ||
		!os.SameFile(prior, after) || !os.SameFile(after, onHandle) || after.Size() > maxLedgerBytes {
		cleanup()
		return nil, nil, ErrLedgerHold
	}
	return f, cleanup, nil
}

// ReadLedgerHead is a locked OS-process read. It returns no capability and is
// never a trustworthy owner head without separately verified owner custody.
func ReadLedgerHead(path string, installation, vault [16]byte) (Head, error) {
	f, closeFn, err := openPinnedLedger(path)
	if err != nil {
		return Head{}, err
	}
	defer closeFn()
	state, err := parseLedger(f, installation, vault)
	return state.head, err
}

// LedgerOwnerLoader adapts this deny-only file to the existing signed TLS
// witness Handler. The Handler will HOLD on any unavailable/invalid ledger.
func LedgerOwnerLoader(path string, installation, vault [16]byte) func() (Head, error) {
	return func() (Head, error) { return ReadLedgerHead(path, installation, vault) }
}

// AppendOwnerDeny compares BOTH the globally witnessed epoch and the exact
// replica floor, then appends only a DENY record under a held kernel lock.
// Replays the full file after Sync on the SAME handle. No delete, truncate,
// replace, repair or positive access API exists. A partial write causes HOLD.
func AppendOwnerDeny(path string, installation, vault, replica [16]byte, expectedGlobal, expectedFloor uint64) (Head, error) {
	if replica == [16]byte{} {
		return Head{}, ErrLedgerHold
	}
	f, closeFn, err := openPinnedLedger(path)
	if err != nil {
		return Head{}, err
	}
	defer closeFn()
	state, err := parseLedger(f, installation, vault)
	if err != nil {
		return Head{}, err
	}
	after, err := appendDenyLocked(f, state, replica, expectedGlobal, expectedFloor)
	if err != nil {
		return Head{}, err
	}
	return after.head, nil
}

// appendDenyLocked MUST only be called while f's OS lock and path-identity
// fence remain held. Both anchored/unanchored flows share identical bytes,
// sync, complete same-handle replay and conditional advance.
func appendDenyLocked(f *os.File, state ledgerState, replica [16]byte, expectedGlobal, expectedFloor uint64) (ledgerState, error) {
	if replica == [16]byte{} {
		return ledgerState{}, ErrLedgerHold
	}
	if state.head.Epoch != expectedGlobal || state.floors[replica] != expectedFloor {
		return ledgerState{}, ErrLedgerStaleCAS
	}
	if state.head.Epoch >= maxLedgerRecords || expectedFloor == math.MaxUint64 {
		return ledgerState{}, ErrLedgerExhausted
	}
	var row [ledgerRecordSize]byte
	binary.LittleEndian.PutUint64(row[:8], expectedGlobal+1)
	copy(row[8:24], replica[:])
	binary.LittleEndian.PutUint64(row[24:32], expectedFloor)
	binary.LittleEndian.PutUint64(row[32:40], expectedFloor+1)
	copy(row[40:72], state.previous[:])
	row[72] = ledgerDenyOpcode
	digest := ledgerRecordHash(row[:80])
	copy(row[80:112], digest[:])
	n, err := f.WriteAt(row[:], state.size)
	if err != nil || n != len(row) {
		return ledgerState{}, ErrLedgerHold
	}
	if err = f.Sync(); err != nil {
		return ledgerState{}, ErrLedgerHold
	}
	after, err := parseLedger(f, state.head.Installation, state.head.Vault)
	if err != nil || after.head.Epoch != expectedGlobal+1 || after.floors[replica] != expectedFloor+1 || after.previous != digest {
		return ledgerState{}, ErrLedgerHold
	}
	return after, nil
}
