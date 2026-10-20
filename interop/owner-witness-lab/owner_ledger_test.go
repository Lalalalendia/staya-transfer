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
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

var testLedgerInstallation = [16]byte{17}
var testLedgerVault = [16]byte{33}
var testLedgerReplica = [16]byte{44}

func preinstallLedger(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "preinstalled-owner-deny.journal")
	header := ledgerHeader(testLedgerInstallation, testLedgerVault)
	if err := os.WriteFile(path, header[:], 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOwnerLedgerColdReopenAndMultiReplicaCAS(t *testing.T) {
	path := preinstallLedger(t)
	zero, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if err != nil || zero.Epoch != 0 || !validHead(zero) {
		t.Fatalf("expected sealed empty map: %+v: %v", zero, err)
	}
	first, err := AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0)
	if err != nil || first.Epoch != 1 || first.DenyDigest == zero.DenyDigest {
		t.Fatalf("append: %+v: %v", first, err)
	}
	if _, err := AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0); !errors.Is(err, ErrLedgerStaleCAS) {
		t.Fatalf("stale global CAS: %v", err)
	}
	second := [16]byte{45}
	another, err := AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, second, 1, 0)
	if err != nil || another.Epoch != 2 {
		t.Fatalf("append second replica: %+v %v", another, err)
	}
	latest, err := AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 2, 1)
	if err != nil || latest.Epoch != 3 {
		t.Fatalf("append first again: %+v %v", latest, err)
	}
	want, err := CanonicalDenyDigest([]Floor{{Replica: testLedgerReplica, Epoch: 2}, {Replica: second, Epoch: 1}})
	if err != nil || latest.DenyDigest != want {
		t.Fatalf("full map not derived from record history: %v", err)
	}
	reopened, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if err != nil || reopened != latest {
		t.Fatalf("cold reopened different head: %+v %v", reopened, err)
	}
	before, _ := os.ReadFile(path)
	if _, err := AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 3, 0); !errors.Is(err, ErrLedgerStaleCAS) {
		t.Fatalf("stale replica floor accepted: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("stale CAS modified journal")
	}
	if _, err := ReadLedgerHead(path, [16]byte{99}, testLedgerVault); !errors.Is(err, ErrLedgerHold) {
		t.Fatalf("wrong installer accepted: %v", err)
	}
	if _, err := ReadLedgerHead(path, testLedgerInstallation, [16]byte{99}); !errors.Is(err, ErrLedgerHold) {
		t.Fatalf("wrong vault accepted: %v", err)
	}
}

func TestOwnerLedgerMissingCorruptTornAndOversizedRemainHold(t *testing.T) {
	path := preinstallLedger(t)
	if _, err := ReadLedgerHead(path+"-missing", testLedgerInstallation, testLedgerVault); !errors.Is(err, ErrLedgerHold) {
		t.Fatalf("missing file accepted: %v", err)
	}
	if _, err := ReadLedgerHead(filepath.Dir(path), testLedgerInstallation, testLedgerVault); !errors.Is(err, ErrLedgerHold) {
		t.Fatalf("directory accepted: %v", err)
	}
	header, _ := os.ReadFile(path)
	wrong := append([]byte(nil), header...)
	wrong[0] ^= 0x80
	if err := os.WriteFile(path, wrong, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault); !errors.Is(err, ErrLedgerHold) {
		t.Fatalf("invalid magic accepted: %v", err)
	}
	if err := os.WriteFile(path, header, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0); err != nil {
		t.Fatal(err)
	}
	valid, _ := os.ReadFile(path)
	flip := append([]byte(nil), valid...)
	flip[len(flip)-1] ^= 0x80
	if err := os.WriteFile(path, flip, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 1, 1); !errors.Is(err, ErrLedgerHold) {
		t.Fatalf("corrupt row accepted: %v", err)
	}
	if err := os.WriteFile(path, append(valid, 0xca, 0xfe), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault); !errors.Is(err, ErrLedgerHold) {
		t.Fatalf("torn row accepted: %v", err)
	}
	if err := os.WriteFile(path, header, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(int64(maxLedgerBytes + 1))
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault); !errors.Is(err, ErrLedgerHold) {
		t.Fatalf("oversized file accepted: %v", err)
	}
}

func TestOwnerLedgerCorrectOldSnapshotReplayIsNotDetected(t *testing.T) {
	path := preinstallLedger(t)
	old, _ := os.ReadFile(path)
	if _, err := AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	h, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if err != nil || h.Epoch != 0 {
		t.Fatalf("expected explicit rollback falsifier, got %+v %v", h, err)
	}
	// This NEGATIVE SECURITY COUNTEREXAMPLE blocks release: a valid old disk
	// snapshot cannot be distinguished from original history by any hash chain.
	// This file is not itself a trustworthy source of grant authorization.
}

func TestOwnerLedgerChildWriter(t *testing.T) {
	if os.Getenv("AKULA_LEDGER_CHILD") != "writer" {
		return
	}
	ready := os.Getenv("AKULA_LEDGER_READY")
	goPath := os.Getenv("AKULA_LEDGER_GO")
	if err := os.WriteFile(ready, []byte("READY"), 0600); err != nil {
		os.Exit(78)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(goPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			os.Exit(78)
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, err := AppendOwnerDeny(os.Getenv("AKULA_LEDGER_PATH"), testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0)
	if err == nil {
		os.Exit(0)
	}
	if errors.Is(err, ErrLedgerStaleCAS) {
		os.Exit(77)
	}
	os.Exit(78)
}

func TestOwnerLedgerTwoIndependentOSProcessesOneCASWinner(t *testing.T) {
	path := preinstallLedger(t)
	directory := filepath.Dir(path)
	gate := filepath.Join(directory, "go")
	executable := os.Args[0]
	spawn := func(ready string) *exec.Cmd {
		c := exec.Command(executable, "-test.run=^TestOwnerLedgerChildWriter$")
		c.Env = append(os.Environ(), "AKULA_LEDGER_CHILD=writer", "AKULA_LEDGER_PATH="+path,
			"AKULA_LEDGER_READY="+ready, "AKULA_LEDGER_GO="+gate)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	aReady := filepath.Join(directory, "a.ready")
	bReady := filepath.Join(directory, "b.ready")
	a := spawn(aReady)
	b := spawn(bReady)
	defer func() {
		if a.ProcessState == nil {
			_ = a.Process.Kill()
			_ = a.Wait()
		}
		if b.ProcessState == nil {
			_ = b.Process.Kill()
			_ = b.Wait()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, ae := os.Stat(aReady)
		_, be := os.Stat(bReady)
		if ae == nil && be == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("two OS child processes did not reach READY barrier")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := os.WriteFile(gate, []byte("GO"), 0600); err != nil {
		t.Fatal(err)
	}
	codes := []int{-1, -1}
	for i, c := range []*exec.Cmd{a, b} {
		err := c.Wait()
		if err == nil {
			codes[i] = 0
		} else if c.ProcessState != nil {
			codes[i] = c.ProcessState.ExitCode()
		}
	}
	sort.Ints(codes)
	if codes[0] != 0 || codes[1] != 77 {
		t.Fatalf("CAS must have one winner and one stale loser; got %v", codes)
	}
	latest, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if err != nil || latest.Epoch != 1 {
		t.Fatalf("CAS race left bad state: %+v %v", latest, err)
	}
}

func TestOwnerLedgerChildPartialExit(t *testing.T) {
	if os.Getenv("AKULA_LEDGER_CHILD") != "torn" {
		return
	}
	f, err := os.OpenFile(os.Getenv("AKULA_LEDGER_PATH"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		os.Exit(78)
	}
	_, err = f.Write([]byte{0xde, 0xad, 0xbe, 0xef, 0x01})
	if err != nil || f.Sync() != nil {
		os.Exit(78)
	}
	os.Exit(79) // no Go deferred cleanup. NOT a real power cut.
}

func TestOwnerLedgerIncompleteChildCrashHoldsAfterColdReopen(t *testing.T) {
	path := preinstallLedger(t)
	c := exec.Command(os.Args[0], "-test.run=^TestOwnerLedgerChildPartialExit$")
	c.Env = append(os.Environ(), "AKULA_LEDGER_CHILD=torn", "AKULA_LEDGER_PATH="+path)
	err := c.Run()
	if err == nil || c.ProcessState == nil || c.ProcessState.ExitCode() != 79 {
		t.Fatalf("expected hard child exit 79: %v", err)
	}
	if _, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault); !errors.Is(err, ErrLedgerHold) {
		t.Fatalf("bad crash recovery: %v", err)
	}
	if _, err := AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0); !errors.Is(err, ErrLedgerHold) {
		t.Fatalf("damaged record silently healed: %v", err)
	}
}

func TestOwnerLedgerFeedsRealSignedMTLSWitnessWithoutGrant(t *testing.T) {
	path := preinstallLedger(t)
	roots, _, serverCert, clientCert := fixtureCerts(t)
	signerPub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(Handler{Loader: LedgerOwnerLoader(path, testLedgerInstallation, testLedgerVault),
		SigningKey: signer, ClientSPKIPin: sha256SPKI(clientCert.parsed)})
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert.cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewClient(roots, clientCert.cert, sha256SPKI(serverCert.parsed), signerPub)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Inspect(context.Background(), srv.URL, stale); got != ConsistentDenialSnapshotOnly {
		t.Fatalf("initial consistency: %v", got)
	}
	current, err := AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Inspect(context.Background(), srv.URL, stale); got != HoldJournalBehind {
		t.Fatalf("stale client accepted: %v", got)
	}
	if got := client.Inspect(context.Background(), srv.URL, current); got != ConsistentDenialSnapshotOnly {
		t.Fatalf("fresh client rejected: %v", got)
	}
	raw, _ := os.ReadFile(path)
	raw[len(raw)-1] ^= 0x40
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if got := client.Inspect(context.Background(), srv.URL, current); got != HoldUnavailable {
		t.Fatalf("damaged owner still signed valid head: %v", got)
	}
}

// Counterexample: cryptographically fresh TLS responses do NOT protect against
// an owner-side rollback when the signing service reads unanchored disk.
// This test deliberately demonstrates a RELEASE BLOCKER rather than success.
func TestOwnerLedgerSignerCannotRecognizeItsOwnValidOldSnapshot(t *testing.T) {
	path := preinstallLedger(t)
	oldBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	oldHead, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if err != nil {
		t.Fatal(err)
	}
	roots, _, serverCert, clientCert := fixtureCerts(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(Handler{Loader: LedgerOwnerLoader(path, testLedgerInstallation, testLedgerVault),
		SigningKey: key, ClientSPKIPin: sha256SPKI(clientCert.parsed)})
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert.cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	client, err := NewClient(roots, clientCert.cert, sha256SPKI(serverCert.parsed), pub)
	if err != nil {
		t.Fatal(err)
	}
	_, err = AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Inspect(context.Background(), server.URL, oldHead); got != HoldJournalBehind {
		t.Fatalf("stale client not blocked: %v", got)
	}
	// A privileged attacker replays the owner journal itself while the
	// TLS signer stays alive. The signed response is genuine and fresh yet
	// reproduces the OLD denial state. External immutable witness is mandatory.
	if err := os.WriteFile(path, oldBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if got := client.Inspect(context.Background(), server.URL, oldHead); got != ConsistentDenialSnapshotOnly {
		t.Fatalf("expected explicit owner rollback falsifier, got %v", got)
	}
}
