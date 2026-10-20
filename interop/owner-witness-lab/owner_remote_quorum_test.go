package ownerwitness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type mutableRemote struct {
	mu   sync.Mutex
	head Head
}

func (s *mutableRemote) read() (Head, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.head, nil }
func (s *mutableRemote) set(h Head)          { s.mu.Lock(); s.head = h; s.mu.Unlock() }

func newQuorumPeer(t *testing.T, h Head) (RemoteDenialPeer, *mutableRemote, func()) {
	t.Helper()
	roots, _, serverCert, clientCert := fixtureCerts(t)
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state := &mutableRemote{head: h}
	srv := httptest.NewUnstartedServer(Handler{Loader: state.read, SigningKey: signer, ClientSPKIPin: sha256SPKI(clientCert.parsed)})
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert.cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	srv.StartTLS()
	client, err := NewClient(roots, clientCert.cert, sha256SPKI(serverCert.parsed), pub)
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	return RemoteDenialPeer{BaseURL: srv.URL, Client: client}, state, srv.Close
}

func TestRemoteQuorumRealMTLSTwoDistinctSignersAndRollbackHold(t *testing.T) {
	ctx := context.Background()
	path := preinstallLedger(t)
	initial, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if err != nil {
		t.Fatal(err)
	}
	a, as, closeA := newQuorumPeer(t, initial)
	defer closeA()
	b, bs, closeB := newQuorumPeer(t, initial)
	defer closeB()
	q, err := NewReadOnlyRemoteQuorum(a, b)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ReadAnchoredDenialHead(ctx, path, testLedgerInstallation, testLedgerVault, q)
	if err != nil || h != initial {
		t.Fatalf("both owners agreed but HOLD: %v", err)
	}
	// The quorum is READ ONLY. It cannot be passed to
	// AppendOwnerDenyWithAnchor (that requires TrustedDenialAnchor).
	if _, ok := any(q).(TrustedDenialAnchor); ok {
		t.Fatal("read quorum acquired unexpected file-write authority")
	}
	afterConstruction, _ := os.ReadFile(path)
	if !bytes.Equal(original, afterConstruction) {
		t.Fatal("read-only quorum modified owner journal")
	}
	if _, err = ReadAnchoredDenialHead(ctx, path, [16]byte{99}, testLedgerVault, q); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("foreign install escaped HOLD: %v", err)
	}
	advanced, err := AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Local changed but neither witness did: fail-closed.
	if _, err = ReadAnchoredDenialHead(ctx, path, testLedgerInstallation, testLedgerVault, q); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("remote witness behind accepted: %v", err)
	}
	// One independently controlled witness advances; other remains old.
	as.set(advanced)
	if _, err = ReadAnchoredDenialHead(ctx, path, testLedgerInstallation, testLedgerVault, q); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("single-witness advance accepted: %v", err)
	}
	bs.set(advanced)
	if h, err = ReadAnchoredDenialHead(ctx, path, testLedgerInstallation, testLedgerVault, q); err != nil || h != advanced {
		t.Fatalf("dual witness agreement refused: %v", err)
	}
	// Owner rollback with even one honest fresh witness cannot pass.
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadAnchoredDenialHead(ctx, path, testLedgerInstallation, testLedgerVault, q); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("old valid local snapshot accepted: %v", err)
	}
	// Forged same epoch but other map by ONE signer must be rejected.
	if _, err = AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, testReplicaB(), 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadAnchoredDenialHead(ctx, path, testLedgerInstallation, testLedgerVault, q); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("equal epoch divergent maps accepted: %v", err)
	}
	// Independently signed, different checkpoint with equal epoch: HOLD.
	bs.set(initial)
	if _, err = ReadAnchoredDenialHead(ctx, path, testLedgerInstallation, testLedgerVault, q); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("two unequal witnesses accepted: %v", err)
	}
	closeB()
	if _, err = ReadAnchoredDenialHead(ctx, path, testLedgerInstallation, testLedgerVault, q); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("offline witness accepted: %v", err)
	}
}

func testReplicaB() [16]byte { return [16]byte{55} }

func TestRemoteQuorumRejectsDuplicateKeyEndpointAndUntrustedTransport(t *testing.T) {
	head := fixtureHead(t)
	a, _, closeA := newQuorumPeer(t, head)
	defer closeA()
	b, _, closeB := newQuorumPeer(t, head)
	defer closeB()
	cases := [][2]RemoteDenialPeer{
		{a, a},
		{a, {BaseURL: b.BaseURL, Client: a.Client}},
		{{BaseURL: "http://untrusted.example", Client: a.Client}, b},
		{{BaseURL: a.BaseURL + "/", Client: a.Client}, b},
		{{BaseURL: "https://user:pass@witness.example", Client: a.Client}, b},
		{{BaseURL: "https://witness.example/api", Client: a.Client}, b},
	}
	for i, c := range cases {
		if _, err := NewReadOnlyRemoteQuorum(c[0], c[1]); !errors.Is(err, ErrAnchorHold) {
			t.Fatalf("accepted invalid peer set %d", i)
		}
	}
	q, err := NewReadOnlyRemoteQuorum(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.Read(context.Background(), head.Installation, [16]byte{99}); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("wrong namespace accepted: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = q.Read(ctx, head.Installation, head.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("cancelled quorum accepted: %v", err)
	}
	// Pinning a foreign signature key preserves TLS success but rejects
	// the signed witness response: no insecure signing fallback.
	alien := *b.Client
	alien.signingKey = bytes.Repeat([]byte{88}, ed25519.PublicKeySize)
	bad, err := NewReadOnlyRemoteQuorum(a, RemoteDenialPeer{BaseURL: b.BaseURL, Client: &alien})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bad.Read(context.Background(), head.Installation, head.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("foreign signature allowed: %v", err)
	}
}

func TestRemoteQuorumTwoColludingValidOldWitnessesStillVulnerable(t *testing.T) {
	path := preinstallLedger(t)
	old, _ := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	a, as, stopA := newQuorumPeer(t, old)
	defer stopA()
	b, bs, stopB := newQuorumPeer(t, old)
	defer stopB()
	q, err := NewReadOnlyRemoteQuorum(a, b)
	if err != nil {
		t.Fatal(err)
	}
	next, err := AppendOwnerDeny(path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	as.set(next)
	bs.set(next)
	oldBytes := ledgerHeader(testLedgerInstallation, testLedgerVault)
	if err = os.WriteFile(path, oldBytes[:], 0600); err != nil {
		t.Fatal(err)
	}
	// Counterexample: two witnesses simultaneously rolled back to matching
	// valid OLD data -> they can freshly sign an old epoch. Need independent
	// non-rollbackable storage and separated admin or a third audit root.
	as.set(old)
	bs.set(old)
	got, err := ReadAnchoredDenialHead(context.Background(), path, testLedgerInstallation, testLedgerVault, q)
	if err != nil || got != old {
		t.Fatalf("expected explicit colluding rollback falsifier, got %v %+v", err, got)
	}
}

// Two genuine OS subprocesses, each with its own TLS and signing key. These
// run on one CI host; they do NOT substitute for two independently administered
// physical hosts or prove durable independent checkpoint custody.
func TestRemoteQuorumTwoSeparateOSWitnessProcesses(t *testing.T) {
	initial := fixtureHead(t)
	dir := t.TempDir()
	type running struct {
		cmd    *exec.Cmd
		url    string
		client *Client
		file   string
	}
	env64 := func(k string, v []byte) string { return k + "=" + base64.StdEncoding.EncodeToString(v) }
	start := func(index int) running {
		roots, caPEM, serverCert, clientCert := fixtureCerts(t)
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewClient(roots, clientCert.cert, sha256SPKI(serverCert.parsed), pub)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, fmt.Sprintf("witness-%d", index))
		writeFixtureHead(t, path, initial)
		ready := filepath.Join(dir, fmt.Sprintf("ready-%d", index))
		c := exec.Command(os.Args[0], "-test.run=^TestChildOwnerProcess$")
		c.Env = append(os.Environ(), "AKULA_OWNER_CHILD=1", "AKULA_OWNER_HEAD="+path, "AKULA_OWNER_READY="+ready,
			env64("AKULA_OWNER_CA", caPEM), env64("AKULA_OWNER_CERT", serverCert.pemCert), env64("AKULA_OWNER_KEY", serverCert.pemKey),
			env64("AKULA_OWNER_CLIENT_PIN", spkiBytes(clientCert.parsed)), env64("AKULA_OWNER_SIGNER", key))
		var logs bytes.Buffer
		c.Stdout = &logs
		c.Stderr = &logs
		if err = c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			content, err := os.ReadFile(ready)
			if err == nil && strings.HasPrefix(string(content), "https://") {
				return running{cmd: c, url: string(content), client: client, file: path}
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("witness %d OS process not ready: %s", index, logs.String())
		return running{}
	}
	a := start(1)
	b := start(2)
	q, err := NewReadOnlyRemoteQuorum(RemoteDenialPeer{BaseURL: a.url, Client: a.client}, RemoteDenialPeer{BaseURL: b.url, Client: b.client})
	if err != nil {
		t.Fatal(err)
	}
	head, err := q.Read(context.Background(), initial.Installation, initial.Vault)
	expected, _ := checkpointFor(initial)
	if err != nil || head != expected {
		t.Fatalf("two real OS witness replies not equal: %v", err)
	}
	// One owner process reopens its backing head per request. A stale peer
	// cannot be smuggled into a cached quorum result.
	newHead := initial
	newHead.Epoch++
	newHead.DenyDigest, _ = CanonicalDenyDigest([]Floor{{Replica: [16]byte{7}, Epoch: 2}})
	writeFixtureHead(t, b.file, newHead)
	if _, err = q.Read(context.Background(), initial.Installation, initial.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("separate OS process state divergence accepted: %v", err)
	}
}
