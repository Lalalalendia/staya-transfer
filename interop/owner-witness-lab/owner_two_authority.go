package ownerwitness

import (
	"context"
	"math"
	"reflect"
)

// RN-4E1b-03c1c0 is a fail-closed TWO-AUTHORITY DENY checkpoint coordinator.
// A second interface implementation on the same machine / same admin account
// does NOT constitute an independent trust domain. The operator must establish
// separate credential, administration, backup and recovery custody externally.
// Both stores implement CAS; this is not an atomic transaction across stores.
// No successful method confers a P2P, File Gate or positive permission.
type TwoAuthorityDenialAnchor struct {
	primary      TrustedDenialAnchor
	fence        TrustedDenialAnchor
	installation [16]byte
	vault        [16]byte
}

var _ TrustedDenialAnchor = (*TwoAuthorityDenialAnchor)(nil)

// NewTwoAuthorityDenialAnchor pins a single namespace and rejects the most
// obvious configuration error: using the identical backend object twice. It
// cannot infer separate operators from distinct Go objects or URLs.
func NewTwoAuthorityDenialAnchor(primary, fence TrustedDenialAnchor, installation, vault [16]byte) (*TwoAuthorityDenialAnchor, error) {
	if primary == nil || fence == nil || installation == [16]byte{} || vault == [16]byte{} || sameAuthorityObject(primary, fence) {
		return nil, ErrAnchorHold
	}
	return &TwoAuthorityDenialAnchor{
		primary: primary, fence: fence, installation: installation, vault: vault,
	}, nil
}

func sameAuthorityObject(a, b TrustedDenialAnchor) bool {
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	if !av.IsValid() || !bv.IsValid() {
		return true
	}
	if (av.Kind() == reflect.Pointer && av.IsNil()) ||
		(bv.Kind() == reflect.Pointer && bv.IsNil()) {
		return true
	}
	// Typical CAS adapters are pointer types. Reject copies of the same
	// instance even if the constructor was called with two interface values.
	if av.Kind() == reflect.Pointer && bv.Kind() == reflect.Pointer &&
		av.Type() == bv.Type() && av.Pointer() == bv.Pointer() {
		return true
	}
	return false
}

func validCASCheckpoint(c DenialCheckpoint) bool {
	h := Head{Installation: c.Installation, Vault: c.Vault, Epoch: c.Epoch, DenyDigest: c.DenyDigest}
	canonical, err := checkpointFor(h)
	return err == nil && canonical == c
}

// Read checks a fresh independent fence first and then the primary. An old,
// restored YDB row cannot be called current while the separately controlled
// fence retains the newer epoch+digest. No last-good-state or cached fallback.
func (a *TwoAuthorityDenialAnchor) Read(ctx context.Context, installation, vault [16]byte) (DenialCheckpoint, error) {
	if a == nil || a.primary == nil || a.fence == nil || ctx == nil || ctx.Err() != nil ||
		installation != a.installation || vault != a.vault {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	watermark, err := a.fence.Read(ctx, installation, vault)
	if err != nil || ctx.Err() != nil || !validCASCheckpoint(watermark) {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	remote, err := a.primary.Read(ctx, installation, vault)
	if err != nil || ctx.Err() != nil || remote != watermark || !validCASCheckpoint(remote) {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	return remote, nil
}

// CompareAndSeal coordinates two *independent* monotone CAS authorities, with
// the fence first. This ordering prevents restoring an older primary row from
// quietly authorizing a replay, *if the fence is independently protected*.
// Fence succeeds, primary fails/crashes => permanently inconsistent, HOLD.
// Fence fails => primary must not be contacted for a write.
// Primary commits but response is lost => HOLD, regardless of a future read.
// There is deliberately no auto-retry or automatic repair/reconciliation.
func (a *TwoAuthorityDenialAnchor) CompareAndSeal(ctx context.Context, before, after DenialCheckpoint) error {
	if a == nil || ctx == nil || ctx.Err() != nil ||
		before.Installation != a.installation || before.Vault != a.vault ||
		after.Installation != a.installation || after.Vault != a.vault ||
		before.Epoch == math.MaxUint64 || after.Epoch != before.Epoch+1 ||
		before.DenyDigest == after.DenyDigest || !validCASCheckpoint(before) || !validCASCheckpoint(after) {
		return ErrAnchorHold
	}
	current, err := a.Read(ctx, a.installation, a.vault)
	if err != nil || current != before || ctx.Err() != nil {
		return ErrAnchorHold
	}
	if err := a.fence.CompareAndSeal(ctx, before, after); err != nil || ctx.Err() != nil {
		return ErrAnchorHold
	}
	if err := a.primary.CompareAndSeal(ctx, before, after); err != nil || ctx.Err() != nil {
		return ErrAnchorHold
	}
	fresh, err := a.Read(ctx, a.installation, a.vault)
	if err != nil || ctx.Err() != nil || fresh != after {
		return ErrAnchorHold
	}
	return nil
}
