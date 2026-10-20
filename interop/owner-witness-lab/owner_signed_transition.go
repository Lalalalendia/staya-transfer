package ownerwitness

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"math"
)

// DENY-only writer authorization research. The policy owner must sign an
// exact one-step transition; its signature does not secure YDB administrators,
// protect a remote editor token or authorize any positive P2P permission.
const signedDenyTransitionDomain = "AKULA_DENY_TRANSITION_V1\x00"

// SignedDenyTransition supplies complete maps: the remote writer must not
// assume two valid checkpoint hashes imply a legitimate DENY event.
type SignedDenyTransition struct {
	Before       DenialCheckpoint
	After        DenialCheckpoint
	Replica      [16]byte
	BeforeFloors []Floor
	AfterFloors  []Floor
}

func signedTransitionBytes(t SignedDenyTransition) []byte {
	out := make([]byte, 0, len(signedDenyTransitionDomain)+32*2+16+8*2)
	out = append(out, signedDenyTransitionDomain...)
	out = append(out, t.Before.Commitment[:]...)
	out = append(out, t.After.Commitment[:]...)
	out = append(out, t.Replica[:]...)
	var epoch [8]byte
	binary.LittleEndian.PutUint64(epoch[:], t.Before.Epoch)
	out = append(out, epoch[:]...)
	binary.LittleEndian.PutUint64(epoch[:], t.After.Epoch)
	out = append(out, epoch[:]...)
	return out
}

func transitionFloors(floors []Floor, globalEpoch uint64) (map[[16]byte]uint64, [32]byte, error) {
	digest, err := CanonicalDenyDigest(floors)
	if err != nil {
		return nil, [32]byte{}, ErrAnchorHold
	}
	m := make(map[[16]byte]uint64, len(floors))
	var total uint64
	for _, floor := range floors {
		if floor.Epoch > math.MaxUint64-total {
			return nil, [32]byte{}, ErrAnchorHold
		}
		total += floor.Epoch
		m[floor.Replica] = floor.Epoch
	}
	if total != globalEpoch {
		return nil, [32]byte{}, ErrAnchorHold
	}
	return m, digest, nil
}

// verifyDenyTransition proves that exactly one replica floor increments once,
// all other floors are untouched, neither map contains duplicate/zero floors,
// global epoch equals the sum of floor counters, and both checkpoints commit to
// their actual complete maps. Reordered maps are acceptable (canonical hash).
func verifyDenyTransition(t SignedDenyTransition) error {
	if t.Replica == [16]byte{} || t.Before.Installation == [16]byte{} ||
		t.Before.Vault == [16]byte{} || t.Before.Installation != t.After.Installation ||
		t.Before.Vault != t.After.Vault || t.Before.Epoch == math.MaxUint64 ||
		t.After.Epoch != t.Before.Epoch+1 {
		return ErrAnchorHold
	}
	for _, cp := range []DenialCheckpoint{t.Before, t.After} {
		got, err := checkpointFor(Head{Installation: cp.Installation, Vault: cp.Vault,
			Epoch: cp.Epoch, DenyDigest: cp.DenyDigest})
		if err != nil || got != cp {
			return ErrAnchorHold
		}
	}
	before, beforeDigest, err := transitionFloors(t.BeforeFloors, t.Before.Epoch)
	if err != nil || beforeDigest != t.Before.DenyDigest {
		return ErrAnchorHold
	}
	after, afterDigest, err := transitionFloors(t.AfterFloors, t.After.Epoch)
	if err != nil || afterDigest != t.After.DenyDigest ||
		len(after) < len(before) || len(after) > len(before)+1 {
		return ErrAnchorHold
	}
	previous := before[t.Replica]
	if previous == math.MaxUint64 || after[t.Replica] != previous+1 {
		return ErrAnchorHold
	}
	for replica, floor := range before {
		if replica == t.Replica {
			continue
		}
		if after[replica] != floor {
			return ErrAnchorHold
		}
	}
	for replica := range after {
		if replica == t.Replica {
			continue
		}
		if _, present := before[replica]; !present {
			return ErrAnchorHold
		}
	}
	return nil
}

// SignedDenyCASGate must run under an independently operated service account.
// It is *not* a network API, a durable audit, or an antirollback root. Its
// pinned policy-owner key cannot be supplied by an untrusted request.
type SignedDenyCASGate struct {
	ownerPublicKey ed25519.PublicKey
	anchor         TrustedDenialAnchor
}

func NewSignedDenyCASGate(ownerPublicKey ed25519.PublicKey, anchor TrustedDenialAnchor) (*SignedDenyCASGate, error) {
	if len(ownerPublicKey) != ed25519.PublicKeySize || anchor == nil {
		return nil, ErrAnchorHold
	}
	return &SignedDenyCASGate{ownerPublicKey: append(ed25519.PublicKey(nil), ownerPublicKey...), anchor: anchor}, nil
}

// Seal checks authorization and policy continuity *before* doing any remote
// writes. A lost acknowledgement always returns HOLD and is never retried;
// success is only a DENY checkpoint transition, never a file grant.
func (g *SignedDenyCASGate) Seal(ctx context.Context, t SignedDenyTransition, signature []byte) error {
	if g == nil || g.anchor == nil || len(g.ownerPublicKey) != ed25519.PublicKeySize ||
		ctx == nil || ctx.Err() != nil || verifyDenyTransition(t) != nil ||
		len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(g.ownerPublicKey, signedTransitionBytes(t), signature) {
		return ErrAnchorHold
	}
	remote, err := g.anchor.Read(ctx, t.Before.Installation, t.Before.Vault)
	if err != nil || ctx.Err() != nil || remote != t.Before {
		return ErrAnchorHold
	}
	if err := g.anchor.CompareAndSeal(ctx, t.Before, t.After); err != nil || ctx.Err() != nil {
		return ErrAnchorHold
	}
	remote, err = g.anchor.Read(ctx, t.After.Installation, t.After.Vault)
	if err != nil || ctx.Err() != nil || remote != t.After {
		return ErrAnchorHold
	}
	return nil
}
