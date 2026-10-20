package ownerwitness

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// RN-4E1b-03c1b4: a deliberately DENY-ONLY checkpoint protocol research gate.
// There is NO trusted backend implementation in this repository. A caller must
// supply an independently operated backend with nonrollbackable CAS semantics.
// A file, a locally cached signature, and this interface are NOT trust roots.
var ErrAnchorHold = errors.New("external owner anchor HOLD: unavailable, inconsistent, or untrusted")

// DenialCheckpoint binds the ENTIRE current denial-floor map to namespace and
// epoch. This is NOT a digest of future positive grants/permissions.
type DenialCheckpoint struct {
	Installation [16]byte
	Vault        [16]byte
	Epoch        uint64
	DenyDigest   [32]byte
	Commitment   [32]byte
}

const checkpointDomain = "AKULA_DENY_ONLY_CHECKPOINT_V1\x00"

func checkpointFor(head Head) (DenialCheckpoint, error) {
	if !validHead(head) {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	var word [8]byte
	binary.LittleEndian.PutUint64(word[:], head.Epoch)
	hasher := sha256.New()
	_, _ = hasher.Write([]byte(checkpointDomain))
	_, _ = hasher.Write(head.Installation[:])
	_, _ = hasher.Write(head.Vault[:])
	_, _ = hasher.Write(word[:])
	_, _ = hasher.Write(head.DenyDigest[:])
	var commitment [32]byte
	copy(commitment[:], hasher.Sum(nil))
	return DenialCheckpoint{
		Installation: head.Installation, Vault: head.Vault,
		Epoch: head.Epoch, DenyDigest: head.DenyDigest, Commitment: commitment,
	}, nil
}

// TrustedDenialAnchor is a PORT only: this code never instantiates or
// authenticates an implementation. The provider must enforce single-copy,
// durable CAS and antirollback against the specified attacker. Read must be a
// fresh authority read (not an eventually consistent or cached copy). Both
// methods must fail closed when availability / identity cannot be established.
// DenialAnchorReader holds no mutation authority. An authenticated quorum of
// remote signers can implement only this interface; it cannot be passed to
// AppendOwnerDenyWithAnchor, which requires a separate sealing capability.
type DenialAnchorReader interface {
	Read(ctx context.Context, installation, vault [16]byte) (DenialCheckpoint, error)
}

// TrustedDenialAnchor is a stronger, separately provisioned mutation port.
// A caller must NEVER promote a read-only witness to this capability by
// wrapping a rejected CAS in a no-op: the journal is written before sealing.
type TrustedDenialAnchor interface {
	DenialAnchorReader
	CompareAndSeal(ctx context.Context, expected, next DenialCheckpoint) error
}

func compareAnchoredState(ctx context.Context, anchor DenialAnchorReader, local Head) (DenialCheckpoint, error) {
	if anchor == nil || ctx == nil || ctx.Err() != nil {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	expected, err := checkpointFor(local)
	if err != nil {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	remote, err := anchor.Read(ctx, local.Installation, local.Vault)
	if err != nil || ctx.Err() != nil || remote != expected {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	return expected, nil
}

// ReadAnchoredDenialHead holds the same OS-process kernel lock used by CAS
// while comparing the ENTIRE ledger and a fresh independent checkpoint.
// The only meaning of a returned Head is "DENY snapshot agrees". It does not
// authorize an endpoint, file write, token, peer or replication operation.
func ReadAnchoredDenialHead(ctx context.Context, path string, installation, vault [16]byte, anchor DenialAnchorReader) (Head, error) {
	if anchor == nil || ctx == nil || ctx.Err() != nil {
		return Head{}, ErrAnchorHold
	}
	f, closeFn, err := openPinnedLedger(path)
	if err != nil {
		return Head{}, ErrAnchorHold
	}
	defer closeFn()
	s, err := parseLedger(f, installation, vault)
	if err != nil {
		return Head{}, ErrAnchorHold
	}
	if _, err = compareAnchoredState(ctx, anchor, s.head); err != nil {
		return Head{}, ErrAnchorHold
	}
	return s.head, nil
}

// AnchoredDenialLoader can be used with the existing signed TLS Handler:
// the handler MUST NOT sign a journal which is missing, behind, ahead of, or
// inconsistent with the independent provider. It still signs no grant.
func AnchoredDenialLoader(ctx context.Context, path string, installation, vault [16]byte, anchor DenialAnchorReader) func() (Head, error) {
	return func() (Head, error) { return ReadAnchoredDenialHead(ctx, path, installation, vault, anchor) }
}

// AppendOwnerDenyWithAnchor intentionally commits ledger first, then seals.
// It holds the OS lock throughout. This is NOT an atomic cross-system write:
// when the process dies between steps, the journal is AHEAD and every future
// check MUST HOLD until independently reviewed recovery. No auto-repair or
// rollback to older state is permitted; even a successful return is not Allow.
func AppendOwnerDenyWithAnchor(ctx context.Context, path string, installation, vault, replica [16]byte,
	expectedGlobal, expectedFloor uint64, anchor TrustedDenialAnchor) (Head, error) {
	if anchor == nil || ctx == nil || ctx.Err() != nil {
		return Head{}, ErrAnchorHold
	}
	if replica == [16]byte{} {
		return Head{}, ErrAnchorHold
	}
	f, closeFn, err := openPinnedLedger(path)
	if err != nil {
		return Head{}, ErrAnchorHold
	}
	defer closeFn()
	before, err := parseLedger(f, installation, vault)
	if err != nil {
		return Head{}, ErrAnchorHold
	}
	if before.head.Epoch != expectedGlobal || before.floors[replica] != expectedFloor {
		return Head{}, ErrLedgerStaleCAS
	}
	oldAnchor, err := compareAnchoredState(ctx, anchor, before.head)
	if err != nil {
		return Head{}, ErrAnchorHold
	}
	// Reuse the tested low-level writer ONLY after lifting it behind a
	// same-handle helper. Calling AppendOwnerDeny here would deadlock / race.
	after, err := appendDenyLocked(f, before, replica, expectedGlobal, expectedFloor)
	if err != nil {
		return Head{}, ErrAnchorHold
	}
	nextAnchor, err := checkpointFor(after.head)
	if err != nil {
		return Head{}, ErrAnchorHold
	}
	if ctx.Err() != nil || anchor.CompareAndSeal(ctx, oldAnchor, nextAnchor) != nil {
		return Head{}, ErrAnchorHold // possible acknowledged or partial seal
	}
	if _, err := compareAnchoredState(ctx, anchor, after.head); err != nil {
		return Head{}, ErrAnchorHold // even after a successful seal response
	}
	return after.head, nil
}
