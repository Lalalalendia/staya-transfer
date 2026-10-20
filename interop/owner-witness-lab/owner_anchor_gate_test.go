package ownerwitness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
)

// This mock models the API contract; it is NOT a trusted storage provider,
// backed by hardware, a second host, or a cryptographically anchored ledger.
type memoryAnchor struct {
	mu             sync.Mutex
	stamp          DenialCheckpoint
	unavailable    bool
	failBeforeSeal bool
	failAfterSeal  bool
	readCount      int
	failReadOn     int
}

func freshMemoryAnchor(t *testing.T, head Head) *memoryAnchor {
	t.Helper()
	c, err := checkpointFor(head)
	if err != nil {
		t.Fatal(err)
	}
	return &memoryAnchor{stamp: c}
}

func (m *memoryAnchor) Read(ctx context.Context, installation, vault [16]byte) (DenialCheckpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readCount++
	if m.unavailable || (m.failReadOn > 0 && m.readCount == m.failReadOn) || ctx.Err() != nil {
		return DenialCheckpoint{}, errors.New("independent anchor read unavailable")
	}
	if m.stamp.Installation != installation || m.stamp.Vault != vault {
		return DenialCheckpoint{}, errors.New("anchor namespace mismatch")
	}
	return m.stamp, nil
}

func (m *memoryAnchor) CompareAndSeal(ctx context.Context, old, next DenialCheckpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil || m.unavailable || m.failBeforeSeal {
		return errors.New("anchor seal unavailable")
	}
	if m.stamp != old || next.Installation != old.Installation || next.Vault != old.Vault ||
		next.Epoch != old.Epoch+1 || next.DenyDigest == old.DenyDigest {
		return errors.New("external anchor stale CAS or invalid transition")
	}
	// Both checkpoints require canonical domain-separated binding.
	h := Head{Installation: next.Installation, Vault: next.Vault, Epoch: next.Epoch, DenyDigest: next.DenyDigest}
	canonical, err := checkpointFor(h)
	if err != nil || canonical != next {
		return errors.New("invalid checkpoint")
	}
	m.stamp = next
	if m.failAfterSeal {
		return errors.New("seal succeeded, response lost")
	}
	return nil
}

func TestAnchorBindsCompleteDenyStateAndNoAutomaticGrant(t *testing.T) {
	path := preinstallLedger(t)
	current, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if err != nil {
		t.Fatal(err)
	}
	anchor := freshMemoryAnchor(t, current)
	ctx := context.Background()
	verified, err := ReadAnchoredDenialHead(ctx, path, testLedgerInstallation, testLedgerVault, anchor)
	if err != nil || verified != current {
		t.Fatalf("read anchored denial: %+v %v", verified, err)
	}
	next, err := AppendOwnerDenyWithAnchor(ctx, path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0, anchor)
	if err != nil || next.Epoch != 1 {
		t.Fatalf("anchored append: %+v %v", next, err)
	}
	if anchor.stamp.Epoch != 1 || anchor.stamp.DenyDigest != next.DenyDigest {
		t.Fatal("external checkpoint does not bind exact epoch and denial digest")
	}
	// A stale local copy may not be considered an authority for granting.
	stale := current
	if stale == next {
		t.Fatal("fixture did not change state")
	}
	got, err := ReadAnchoredDenialHead(ctx, path, testLedgerInstallation, testLedgerVault, anchor)
	if err != nil || got != next {
		t.Fatalf("post-seal readback: %v %+v", err, got)
	}
	if _, err := AppendOwnerDenyWithAnchor(ctx, path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0, anchor); !errors.Is(err, ErrLedgerStaleCAS) {
		t.Fatalf("stale CAS modified state: %v", err)
	}
	if _, err := ReadAnchoredDenialHead(ctx, path, testLedgerInstallation, [16]byte{90}, anchor); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("wrong vault accepted: %v", err)
	}
}

func TestOwnerRollbackIsHeldAgainstIndependentNewerCheckpoint(t *testing.T) {
	path := preinstallLedger(t)
	oldBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if err != nil {
		t.Fatal(err)
	}
	anchor := freshMemoryAnchor(t, initial)
	next, err := AppendOwnerDenyWithAnchor(context.Background(), path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, oldBytes, 0600); err != nil {
		t.Fatal(err)
	}
	unanchored, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if err != nil || unanchored.Epoch != 0 {
		t.Fatal("counterexample invalid: old bytes should parse")
	}
	if _, err := ReadAnchoredDenialHead(context.Background(), path, testLedgerInstallation, testLedgerVault, anchor); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("valid old file was not held: %v", err)
	}
	// Even replaying a different valid denial map with the SAME epoch must hold.
	if err := os.WriteFile(path, oldBytes, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, [16]byte{55}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAnchoredDenialHead(context.Background(), path, testLedgerInstallation, testLedgerVault, anchor); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("equal epoch, divergent denial map accepted: %v", err)
	}
	if anchor.stamp.Epoch != 1 || anchor.stamp.DenyDigest != next.DenyDigest {
		t.Fatal("anchor unexpectedly changed")
	}
}

func TestOwnerAnchorUnavailableDoesNotWriteAndNeverBootstraps(t *testing.T) {
	path := preinstallLedger(t)
	original, _ := os.ReadFile(path)
	first, _ := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	anchor := freshMemoryAnchor(t, first)
	anchor.unavailable = true
	if _, err := AppendOwnerDenyWithAnchor(context.Background(), path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0, anchor); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("unavailable anchor permitted CAS: %v", err)
	}
	now, _ := os.ReadFile(path)
	if !bytes.Equal(now, original) {
		t.Fatal("anchor unavailable still mutated ledger")
	}
	if _, err := ReadAnchoredDenialHead(context.Background(), path, testLedgerInstallation, testLedgerVault, nil); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("missing external trust bootstrapped: %v", err)
	}
	if _, err := ReadAnchoredDenialHead(context.Background(), path, testLedgerInstallation, testLedgerVault, anchor); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("offline external checkpoint accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AppendOwnerDenyWithAnchor(ctx, path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0, anchor); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("cancelled request allowed: %v", err)
	}
}

func TestJournalAheadOfAnchorAfterCrashBoundaryIsHoldNoAutomaticRepair(t *testing.T) {
	path := preinstallLedger(t)
	initial, _ := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	anchor := freshMemoryAnchor(t, initial)
	anchor.failBeforeSeal = true
	if _, err := AppendOwnerDenyWithAnchor(context.Background(), path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0, anchor); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("failure to seal should not return success: %v", err)
	}
	local, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if err != nil || local.Epoch != 1 {
		t.Fatal("expected durable ledger ahead of anchor", err, local.Epoch)
	}
	if anchor.stamp.Epoch != 0 {
		t.Fatal("failed anchor write unexpectedly modified provider")
	}
	anchor.failBeforeSeal = false
	if _, err := ReadAnchoredDenialHead(context.Background(), path, testLedgerInstallation, testLedgerVault, anchor); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("unsealed ledger promoted: %v", err)
	}
	if _, err := AppendOwnerDenyWithAnchor(context.Background(), path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 1, 1, anchor); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("post-crash retry must HOLD: %v", err)
	}
	now, _ := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if now.Epoch != 1 {
		t.Fatal("conflicted ledger auto-advanced")
	}
}

func TestAnchorAheadOfJournalAndUnknownCommitResultAreHold(t *testing.T) {
	path := preinstallLedger(t)
	initial, _ := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	anchor := freshMemoryAnchor(t, initial)
	// Simulate seal-before-journal crash by advancing the independent root.
	nextDigest, err := CanonicalDenyDigest([]Floor{{Replica: testLedgerReplica, Epoch: 1}})
	if err != nil {
		t.Fatal(err)
	}
	advanced := Head{Installation: initial.Installation, Vault: initial.Vault, Epoch: 1, DenyDigest: nextDigest}
	nextCheckpoint, _ := checkpointFor(advanced)
	anchor.stamp = nextCheckpoint
	if _, err := ReadAnchoredDenialHead(context.Background(), path, testLedgerInstallation, testLedgerVault, anchor); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("anchor-ahead state accepted: %v", err)
	}
	// Unknown whether a successful seal was ACKed must still fail the caller.
	anchor.stamp, _ = checkpointFor(initial)
	anchor.failAfterSeal = true
	if _, err := AppendOwnerDenyWithAnchor(context.Background(), path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0, anchor); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("lost CAS reply treated as success: %v", err)
	}
	head, err := ReadAnchoredDenialHead(context.Background(), path, testLedgerInstallation, testLedgerVault, anchor)
	if err != nil || head.Epoch != 1 {
		t.Fatalf("independent post-error diagnostic mismatch: %v", err)
	}
}

func TestUntrustedCheckpointIsRefusedAndMTLSSignerFailsClosed(t *testing.T) {
	path := preinstallLedger(t)
	initial, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if err != nil {
		t.Fatal(err)
	}
	anchor := freshMemoryAnchor(t, initial)
	forged := anchor.stamp
	forged.Commitment[0] ^= 0x80
	anchor.stamp = forged
	if _, err := ReadAnchoredDenialHead(context.Background(), path, testLedgerInstallation, testLedgerVault, anchor); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("invalid content commitment accepted: %v", err)
	}
	anchor.stamp, _ = checkpointFor(initial)
	roots, _, serverCert, clientCert := fixtureCerts(t)
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(Handler{Loader: AnchoredDenialLoader(context.Background(), path, testLedgerInstallation, testLedgerVault, anchor),
		SigningKey: signer, ClientSPKIPin: sha256SPKI(clientCert.parsed)})
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert.cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewClient(roots, clientCert.cert, sha256SPKI(serverCert.parsed), pub)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Inspect(context.Background(), srv.URL, initial); got != ConsistentDenialSnapshotOnly {
		t.Fatalf("expected denial-only diagnostic: %s", got)
	}
	_, err = AppendOwnerDenyWithAnchor(context.Background(), path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Inspect(context.Background(), srv.URL, initial); got != HoldJournalBehind {
		t.Fatalf("newer anchor should show old local as behind: %s", got)
	}
	anchor.unavailable = true
	if got := client.Inspect(context.Background(), srv.URL, initial); got != HoldUnavailable {
		t.Fatalf("signed stale state while anchor offline: %s", got)
	}
}

func TestAnchoredCASOneWinnerForTwoConcurrentCalls(t *testing.T) {
	path := preinstallLedger(t)
	initial, _ := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	anchor := freshMemoryAnchor(t, initial)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := AppendOwnerDenyWithAnchor(context.Background(), path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0, anchor)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	ok, stale := 0, 0
	for err := range results {
		if err == nil {
			ok++
		} else if errors.Is(err, ErrLedgerStaleCAS) {
			stale++
		} else {
			t.Fatalf("unexpected CAS failure: %v", err)
		}
	}
	if ok != 1 || stale != 1 {
		t.Fatalf("CAS winners=%d stale=%d", ok, stale)
	}
}
