package ownerwitness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"math"
	"sync"
	"testing"
)

func signedTransitionFixture(t *testing.T, beforeFloors, afterFloors []Floor, beforeEpoch uint64, replica [16]byte) SignedDenyTransition {
	t.Helper()
	beforeDigest, err := CanonicalDenyDigest(beforeFloors)
	if err != nil {
		t.Fatal(err)
	}
	afterDigest, err := CanonicalDenyDigest(afterFloors)
	if err != nil {
		t.Fatal(err)
	}
	before, err := checkpointFor(Head{Installation: testLedgerInstallation, Vault: testLedgerVault,
		Epoch: beforeEpoch, DenyDigest: beforeDigest})
	if err != nil {
		t.Fatal(err)
	}
	after, err := checkpointFor(Head{Installation: testLedgerInstallation, Vault: testLedgerVault,
		Epoch: beforeEpoch + 1, DenyDigest: afterDigest})
	if err != nil {
		t.Fatal(err)
	}
	return SignedDenyTransition{Before: before, After: after, Replica: replica,
		BeforeFloors: beforeFloors, AfterFloors: afterFloors}
}

func signTransition(t *testing.T, transition SignedDenyTransition) (ed25519.PublicKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, ed25519.Sign(priv, signedTransitionBytes(transition))
}

func TestSignedDenyGatewayRealHTTPSReadCASAndReplayHold(t *testing.T) {
	oldDigest, err := CanonicalDenyDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldHead := Head{Installation: testLedgerInstallation, Vault: testLedgerVault,
		Epoch: 0, DenyDigest: oldDigest}
	provider, state := newYDBFixture(t, oldHead)
	transition := signedTransitionFixture(t, nil, []Floor{{Replica: testLedgerReplica, Epoch: 1}}, 0, testLedgerReplica)
	pub, sig := signTransition(t, transition)
	gate, err := NewSignedDenyCASGate(pub, provider)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Seal(context.Background(), transition, sig); err != nil {
		t.Fatalf("valid owner-signed monotone DENY transition refused: %v", err)
	}
	got, err := provider.Read(context.Background(), testLedgerInstallation, testLedgerVault)
	if err != nil || got != transition.After {
		t.Fatalf("remote state did not advance: %v", err)
	}
	if err := gate.Seal(context.Background(), transition, sig); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("replayed signed transition was accepted: %v", err)
	}
	state.mu.Lock()
	updates := state.totalUpdate
	state.mu.Unlock()
	if updates != 1 {
		t.Fatalf("replay caused remote retry: %d writes", updates)
	}
}

func TestSignedDenyGatewayRejectsForgedChangesBeforeAnyHTTPRequest(t *testing.T) {
	first := [16]byte{25}
	second := [16]byte{26}
	third := [16]byte{27}
	baselineBefore := []Floor{{Replica: first, Epoch: 1}, {Replica: second, Epoch: 2}}
	baselineAfter := []Floor{{Replica: first, Epoch: 2}, {Replica: second, Epoch: 2}}
	tests := []struct {
		name   string
		change func(*SignedDenyTransition)
	}{
		{"valid signature wrong owner key", func(*SignedDenyTransition) {}},
		{"unrelated floor decreased and new floor inserted", func(tr *SignedDenyTransition) {
			tr.AfterFloors = []Floor{{Replica: first, Epoch: 2}, {Replica: second, Epoch: 1}, {Replica: third, Epoch: 1}}
			d, _ := CanonicalDenyDigest(tr.AfterFloors)
			tr.After, _ = checkpointFor(Head{Installation: tr.After.Installation, Vault: tr.After.Vault, Epoch: tr.After.Epoch, DenyDigest: d})
		}},
		{"second floor also incremented", func(tr *SignedDenyTransition) {
			tr.AfterFloors = []Floor{{Replica: first, Epoch: 2}, {Replica: second, Epoch: 3}}
			d, _ := CanonicalDenyDigest(tr.AfterFloors)
			tr.After, _ = checkpointFor(Head{Installation: tr.After.Installation, Vault: tr.After.Vault, Epoch: tr.After.Epoch, DenyDigest: d})
		}},
		{"revoke step removed a floor", func(tr *SignedDenyTransition) {
			tr.AfterFloors = []Floor{{Replica: first, Epoch: 2}}
			d, _ := CanonicalDenyDigest(tr.AfterFloors)
			tr.After, _ = checkpointFor(Head{Installation: tr.After.Installation, Vault: tr.After.Vault, Epoch: tr.After.Epoch, DenyDigest: d})
		}},
		{"duplicate replica", func(tr *SignedDenyTransition) {
			tr.AfterFloors = append(tr.AfterFloors, Floor{Replica: first, Epoch: 2})
		}},
		{"forged before digest", func(tr *SignedDenyTransition) {
			tr.Before.DenyDigest[0] ^= 1
		}},
		{"namespace altered", func(tr *SignedDenyTransition) {
			tr.After.Vault[0] ^= 1
		}},
		{"global version skipped", func(tr *SignedDenyTransition) {
			tr.After.Epoch++
		}},
		{"wrong source epoch sum", func(tr *SignedDenyTransition) {
			tr.BeforeFloors[0].Epoch++
		}},
		{"not authorized replica", func(tr *SignedDenyTransition) {
			tr.Replica = third
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := signedTransitionFixture(t,
				append([]Floor(nil), baselineBefore...), append([]Floor(nil), baselineAfter...), 3, first)
			tc.change(&tr)
			pub, sig := signTransition(t, tr)
			if tc.name == "valid signature wrong owner key" {
				other, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				pub = other
			}
			p, state := newYDBFixture(t, Head{Installation: testLedgerInstallation, Vault: testLedgerVault,
				Epoch: tr.Before.Epoch, DenyDigest: tr.Before.DenyDigest})
			gate, err := NewSignedDenyCASGate(pub, p)
			if err != nil {
				t.Fatal(err)
			}
			if err := gate.Seal(context.Background(), tr, sig); !errors.Is(err, ErrAnchorHold) {
				t.Fatalf("forged DENY transition passed: %v", err)
			}
			state.mu.Lock()
			gets, puts := state.totalGet, state.totalUpdate
			state.mu.Unlock()
			if gets != 0 || puts != 0 {
				t.Fatalf("invalid transition contacted remote YDB: reads=%d updates=%d", gets, puts)
			}
		})
	}
}

func TestSignedDenyGatewayTwoWritersOneCASAndAmbiguousAckHolds(t *testing.T) {
	transition := signedTransitionFixture(t, nil, []Floor{{Replica: testLedgerReplica, Epoch: 1}}, 0, testLedgerReplica)
	pub, sig := signTransition(t, transition)
	p, state := newYDBFixture(t, Head{Installation: transition.Before.Installation,
		Vault: transition.Before.Vault, Epoch: transition.Before.Epoch, DenyDigest: transition.Before.DenyDigest})
	gate, err := NewSignedDenyCASGate(pub, p)
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	out := make(chan error, 2)
	var started sync.WaitGroup
	started.Add(2)
	for i := 0; i < 2; i++ {
		go func() { started.Done(); <-ready; out <- gate.Seal(context.Background(), transition, sig) }()
	}
	started.Wait()
	close(ready)
	a, b := <-out, <-out
	if !((a == nil && errors.Is(b, ErrAnchorHold)) || (b == nil && errors.Is(a, ErrAnchorHold))) {
		t.Fatalf("two owner-signed writes were not serialized by CAS: %v and %v", a, b)
	}
	state.mu.Lock()
	writes := state.totalUpdate
	state.mu.Unlock()
	if writes < 1 || writes > 2 {
		t.Fatalf("unexpected CAS attempts: %d", writes)
	}
}

func TestSignedDenyGatewayPowerfulDBAdminStillCanRollbackAndReplay(t *testing.T) {
	transition := signedTransitionFixture(t, nil, []Floor{{Replica: testLedgerReplica, Epoch: 1}}, 0, testLedgerReplica)
	pub, sig := signTransition(t, transition)
	p, state := newYDBFixture(t, Head{Installation: transition.Before.Installation,
		Vault: transition.Before.Vault, Epoch: transition.Before.Epoch, DenyDigest: transition.Before.DenyDigest})
	gate, err := NewSignedDenyCASGate(pub, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Seal(context.Background(), transition, sig); err != nil {
		t.Fatal(err)
	}
	// This is a release-blocking counterexample: compromised administrator can
	// restore the previous correct DB row, making the identical old signature
	// valid again. Cryptographic authorization cannot replace a trust anchor.
	state.mu.Lock()
	state.row = rowFor(transition.Before)
	state.mu.Unlock()
	if err := gate.Seal(context.Background(), transition, sig); err != nil {
		t.Fatalf("rollback falsifier should demonstrate vulnerability, got %v", err)
	}
}

func TestSignedDenyGatewayRejectsMissingAuthorityAndOverflow(t *testing.T) {
	transition := signedTransitionFixture(t, nil, []Floor{{Replica: testLedgerReplica, Epoch: 1}}, 0, testLedgerReplica)
	pub, sig := signTransition(t, transition)
	p, _ := newYDBFixture(t, Head{Installation: transition.Before.Installation,
		Vault: transition.Before.Vault, Epoch: transition.Before.Epoch, DenyDigest: transition.Before.DenyDigest})
	if _, err := NewSignedDenyCASGate(nil, p); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("nil signing key accepted")
	}
	if _, err := NewSignedDenyCASGate(pub, nil); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("nil remote authority accepted")
	}
	gate, err := NewSignedDenyCASGate(pub, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Seal(context.Background(), transition, nil); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("unsigned transition accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := gate.Seal(ctx, transition, sig); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("cancelled request accepted")
	}
	if err := (*SignedDenyCASGate)(nil).Seal(context.Background(), transition, sig); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("nil owner gate accepted")
	}
	overflow := transition
	overflow.Before.Epoch = math.MaxUint64
	overflow.After.Epoch = 0
	if verifyDenyTransition(overflow) == nil {
		t.Fatal("global version rollover was accepted")
	}
}
