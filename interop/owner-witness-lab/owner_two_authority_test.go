package ownerwitness

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
)

func newTwoAuthorityFixture(t *testing.T) (SignedDenyTransition, *SignedDenyCASGate, *documentAPIFixture, *memoryAnchor, []byte, *TwoAuthorityDenialAnchor) {
	t.Helper()
	tr, pub, sig := freshDenyTransition(t)
	primary, state := newYDBFixture(t, Head{Installation: tr.Before.Installation, Vault: tr.Before.Vault,
		Epoch: tr.Before.Epoch, DenyDigest: tr.Before.DenyDigest})
	fence := freshMemoryAnchor(t, Head{Installation: tr.Before.Installation, Vault: tr.Before.Vault,
		Epoch: tr.Before.Epoch, DenyDigest: tr.Before.DenyDigest})
	dual, err := NewTwoAuthorityDenialAnchor(primary, fence, tr.Before.Installation, tr.Before.Vault)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := NewSignedDenyCASGate(pub, dual)
	if err != nil {
		t.Fatal(err)
	}
	return tr, gate, state, fence, sig, dual
}

func TestTwoAuthoritySignedDenyUsesRealYDBHTTPSAndHoldsRestoredPrimary(t *testing.T) {
	tr, gate, db, fence, sig, paired := newTwoAuthorityFixture(t)
	if err := gate.Seal(context.Background(), tr, sig); err != nil {
		t.Fatalf("legitimate signed denial held: %v", err)
	}
	db.mu.Lock()
	n := db.totalUpdate
	db.mu.Unlock()
	if n != 1 {
		t.Fatalf("remote conditional writes: %d", n)
	}
	if fence.stamp != tr.After {
		t.Fatal("independent fence did not advance")
	}
	if state, err := paired.Read(context.Background(), tr.After.Installation, tr.After.Vault); err != nil || state != tr.After {
		t.Fatalf("post-CAS pair mismatch: %v %v", state, err)
	}
	// Privileged YDB operator can restore the exact old valid database row,
	// but cannot restore this independently administered high-water witness.
	db.mu.Lock()
	db.row = rowFor(tr.Before)
	writes := db.totalUpdate
	db.mu.Unlock()
	if _, err := paired.Read(context.Background(), tr.Before.Installation, tr.Before.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("restored YDB row matched newer independent witness: %v", err)
	}
	if err := gate.Seal(context.Background(), tr, sig); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("replayed old owner signature escaped independent fence: %v", err)
	}
	db.mu.Lock()
	after := db.totalUpdate
	db.mu.Unlock()
	if after != writes {
		t.Fatal("rollback triggered a new YDB UpdateItem")
	}
}

func TestTwoAuthorityFenceOfflineLeavesPrimaryUnchanged(t *testing.T) {
	tr, gate, db, fence, sig, _ := newTwoAuthorityFixture(t)
	fence.unavailable = true
	if err := gate.Seal(context.Background(), tr, sig); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("offline fence allowed YDB mutation")
	}
	db.mu.Lock()
	n := db.totalUpdate
	db.mu.Unlock()
	if n != 0 {
		t.Fatalf("YDB received %d writes with offline fence", n)
	}
	fence.unavailable = false
	fence.failBeforeSeal = true
	if err := gate.Seal(context.Background(), tr, sig); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("failed fence seal allowed YDB mutation")
	}
	db.mu.Lock()
	n = db.totalUpdate
	db.mu.Unlock()
	if n != 0 || fence.stamp != tr.Before {
		t.Fatal("failed fence seal changed external state")
	}
}

type failPrimaryCAS struct {
	TrustedDenialAnchor
	attempted int
}

func (a *failPrimaryCAS) CompareAndSeal(ctx context.Context, before, after DenialCheckpoint) error {
	a.attempted++
	return ErrAnchorHold
}

func TestTwoAuthorityFenceAheadIfPrimaryCASFailsIsPermanentHold(t *testing.T) {
	tr, _, db, fence, _, pair := newTwoAuthorityFixture(t)
	broken := &failPrimaryCAS{TrustedDenialAnchor: pair.primary}
	pair.primary = broken
	// The independent fence succeeds, then YDB returns an error. Even if a
	// technician clears the error, no automatic one-sided replay is allowed.
	if err := pair.CompareAndSeal(context.Background(), tr.Before, tr.After); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("ambiguous cross-domain partial write accepted: %v", err)
	}
	if fence.stamp != tr.After {
		t.Fatal("test missed fence-first crash boundary")
	}
	if _, err := pair.Read(context.Background(), tr.Before.Installation, tr.Before.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("fence ahead of primary not detected: %v", err)
	}
	if err := pair.CompareAndSeal(context.Background(), tr.Before, tr.After); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("partially committed pair was retried: %v", err)
	}
	db.mu.Lock()
	writes := db.totalUpdate
	db.mu.Unlock()
	if writes != 0 || broken.attempted != 1 {
		t.Fatalf("bad partial CAS result, YDB writes=%d, failed primary attempts=%d", writes, broken.attempted)
	}
}

func TestTwoAuthorityUnknownFenceAckHoldsWithoutPrimaryMutation(t *testing.T) {
	tr, _, db, fence, _, pair := newTwoAuthorityFixture(t)
	fence.failAfterSeal = true // durable fence commit succeeded, reply was lost
	if err := pair.CompareAndSeal(context.Background(), tr.Before, tr.After); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("lost fence ack treated as success: %v", err)
	}
	if fence.stamp != tr.After {
		t.Fatal("no actual simulated fence commit")
	}
	db.mu.Lock()
	writes := db.totalUpdate
	db.mu.Unlock()
	if writes != 0 {
		t.Fatalf("unknown fence response allowed YDB write: %d", writes)
	}
	if _, err := pair.Read(context.Background(), tr.Before.Installation, tr.Before.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("ambiguous seal became consistent")
	}
}

func TestTwoAuthorityLostPrimaryAcknowledgementStaysHoldEvenWhenBothMatch(t *testing.T) {
	tr := signedTransitionFixture(t, nil, []Floor{{Replica: testLedgerReplica, Epoch: 1}}, 0, testLedgerReplica)
	primary := freshMemoryAnchor(t, Head{Installation: tr.Before.Installation, Vault: tr.Before.Vault,
		Epoch: tr.Before.Epoch, DenyDigest: tr.Before.DenyDigest})
	fence := freshMemoryAnchor(t, Head{Installation: tr.Before.Installation, Vault: tr.Before.Vault,
		Epoch: tr.Before.Epoch, DenyDigest: tr.Before.DenyDigest})
	primary.failAfterSeal = true
	paired, err := NewTwoAuthorityDenialAnchor(primary, fence, tr.Before.Installation, tr.Before.Vault)
	if err != nil {
		t.Fatal(err)
	}
	if err := paired.CompareAndSeal(context.Background(), tr.Before, tr.After); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("lost primary acknowledgement treated as success: %v", err)
	}
	if state, err := paired.Read(context.Background(), tr.Before.Installation, tr.Before.Vault); err != nil || state != tr.After {
		t.Fatalf("later diagnostic should find both advanced, never grant: %v %v", state, err)
	}
}

func TestTwoAuthorityOneCASWinnerUnderConcurrency(t *testing.T) {
	tr, gate, db, _, sig, _ := newTwoAuthorityFixture(t)
	start := make(chan struct{})
	outcome := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for i := 0; i < 2; i++ {
		go func() { ready.Done(); <-start; outcome <- gate.Seal(context.Background(), tr, sig) }()
	}
	ready.Wait()
	close(start)
	a, b := <-outcome, <-outcome
	if !((a == nil && errors.Is(b, ErrAnchorHold)) || (b == nil && errors.Is(a, ErrAnchorHold))) {
		t.Fatalf("expected exactly one two-authority CAS winner: %v, %v", a, b)
	}
	db.mu.Lock()
	n := db.totalUpdate
	db.mu.Unlock()
	if n != 1 {
		t.Fatalf("expected 1 remote write, got %d", n)
	}
}

func TestTwoAuthorityMustBeTrulyIndependentAndNamespaceBound(t *testing.T) {
	tr, _, _, fence, _, pair := newTwoAuthorityFixture(t)
	if _, err := NewTwoAuthorityDenialAnchor(fence, fence, tr.Before.Installation, tr.Before.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("accepted same authority twice: %v", err)
	}
	if _, err := NewTwoAuthorityDenialAnchor(fence, nil, tr.Before.Installation, tr.Before.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("accepted missing independent authority: %v", err)
	}
	var nilMemory *memoryAnchor
	if _, err := NewTwoAuthorityDenialAnchor(fence, nilMemory, tr.Before.Installation, tr.Before.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("accepted typed nil authority: %v", err)
	}
	if _, err := pair.Read(context.Background(), tr.Before.Installation, [16]byte{11}); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("accepted different vault: %v", err)
	}
	corrupt := tr.Before
	corrupt.Commitment[0] ^= 0x80
	if err := pair.CompareAndSeal(context.Background(), corrupt, tr.After); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("noncanonical old commitment admitted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pair.CompareAndSeal(ctx, tr.Before, tr.After); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("cancelled dual CAS admitted")
	}
}

func TestTwoAuthorityBothRestoredStillVulnerableCounterexample(t *testing.T) {
	tr, gate, db, fence, sig, _ := newTwoAuthorityFixture(t)
	if err := gate.Seal(context.Background(), tr, sig); err != nil {
		t.Fatal(err)
	}
	// This is NOT a PASS on antirollback: the independently controlled fence
	// must be nonrollbackable against the attacker for this design to help.
	db.mu.Lock()
	db.row = rowFor(tr.Before)
	db.mu.Unlock()
	fence.mu.Lock()
	fence.stamp = tr.Before
	fence.mu.Unlock()
	if err := gate.Seal(context.Background(), tr, sig); err != nil {
		t.Fatalf("dual administrative rollback falsifier should succeed, got %v", err)
	}
}

func TestTwoAuthorityFullMTLSGatewayBlocksPrimaryRollback(t *testing.T) {
	tr, gate, db, _, sig, _ := newTwoAuthorityFixture(t)
	roots, _, serverCert, clientCert := fixtureCerts(t)
	handler, err := NewOwnerDenyGateway(gate, sha256SPKI(clientCert.parsed), tr.Before.Installation, tr.Before.Vault)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert.cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewOwnerDenyGatewayClient(roots, clientCert.cert, sha256SPKI(serverCert.parsed))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SubmitDeny(context.Background(), srv.URL, tr, sig); err != nil {
		t.Fatalf("valid signed mTLS transition denied: %v", err)
	}
	db.mu.Lock()
	db.row = rowFor(tr.Before)
	writes := db.totalUpdate
	db.mu.Unlock()
	if err := client.SubmitDeny(context.Background(), srv.URL, tr, sig); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("restored YDB row escaped independent high-water fence: %v", err)
	}
	db.mu.Lock()
	after := db.totalUpdate
	db.mu.Unlock()
	if after != writes {
		t.Fatal("mTLS gateway replay caused a YDB CAS")
	}
}
