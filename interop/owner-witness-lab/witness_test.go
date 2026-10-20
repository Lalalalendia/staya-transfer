package ownerwitness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type identity struct {
	cert            tls.Certificate
	pemCert, pemKey []byte
	parsed          *x509.Certificate
}

func fixtureCerts(t *testing.T) (*x509.CertPool, []byte, identity, identity) {
	t.Helper()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Akula lab root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	issue := func(serial int64, server bool) identity {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Akula witness test"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		if !server {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		tlsCert, err := tls.X509KeyPair(pemCert, pemKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return identity{cert: tlsCert, pemCert: pemCert, pemKey: pemKey, parsed: parsed}
	}
	return pool, caPEM, issue(2, true), issue(3, false)
}

func fixtureHead(t *testing.T) Head {
	t.Helper()
	digest, err := CanonicalDenyDigest([]Floor{{Replica: [16]byte{7}, Epoch: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return Head{Installation: [16]byte{1}, Vault: [16]byte{2}, Epoch: 1, DenyDigest: digest}
}

func writeFixtureHead(t *testing.T, path string, h Head) {
	t.Helper()
	var nonce [32]byte
	nonce[0] = 1
	payload := encode(h, nonce)
	// Wire payload is domain | canonical head | nonce.
	frame := append(append([]byte(nil), headMagic[:]...), payload[len(domain):len(payload)-32]...)
	sum := sha256.Sum256(frame)
	frame = append(frame, sum[:]...)
	if len(frame) != headFileSize {
		t.Fatalf("incorrect fixture length %d", len(frame))
	}
	if err := os.WriteFile(path, frame, 0600); err != nil {
		t.Fatal(err)
	}
}

func serverFixture(t *testing.T, head Head) (string, *Client, func(), ed25519.PrivateKey) {
	t.Helper()
	roots, _, serverCert, clientCert := fixtureCerts(t)
	signerPub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(Handler{Loader: func() (Head, error) { return head, nil },
		SigningKey: signer, ClientSPKIPin: sha256SPKI(clientCert.parsed)})
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert.cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	srv.StartTLS()
	client, err := NewClient(roots, clientCert.cert, sha256SPKI(serverCert.parsed), signerPub)
	if err != nil {
		t.Fatal(err)
	}
	return srv.URL, client, srv.Close, signer
}

func TestCanonicalDenyMapAndMalformedHead(t *testing.T) {
	a := []Floor{{Replica: [16]byte{5}, Epoch: 2}, {Replica: [16]byte{4}, Epoch: 3}}
	h1, err := CanonicalDenyDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := CanonicalDenyDigest([]Floor{a[1], a[0]})
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("sorting changed digest")
	}
	if _, err := CanonicalDenyDigest([]Floor{a[0], a[0]}); err == nil {
		t.Fatal("duplicate allowed")
	}
	if _, err := CanonicalDenyDigest([]Floor{{Replica: [16]byte{4}}}); err == nil {
		t.Fatal("zero floor allowed")
	}
	head := fixtureHead(t)
	var nonce [32]byte
	nonce[0] = 3
	frame := encode(head, nonce)
	if _, _, err := decode(frame[:len(frame)-1]); err == nil {
		t.Fatal("short frame allowed")
	}
	frame[0] ^= 1
	if _, _, err := decode(frame); err == nil {
		t.Fatal("wrong domain allowed")
	}
}

func TestRealTLSAndFreshSignedHeadRefuseRollback(t *testing.T) {
	head := fixtureHead(t)
	url, client, closeServer, _ := serverFixture(t, head)
	defer closeServer()
	ctx := context.Background()
	if got := client.Inspect(ctx, url, head); got != ConsistentDenialSnapshotOnly {
		t.Fatalf("matching: %s", got)
	}
	old := head
	old.Epoch = 0
	if got := client.Inspect(ctx, url, old); got != HoldJournalBehind {
		t.Fatalf("rolled back local: %s", got)
	}
	future := head
	future.Epoch = 2
	if got := client.Inspect(ctx, url, future); got != HoldJournalAhead {
		t.Fatalf("unsealed local: %s", got)
	}
	changed := head
	changed.DenyDigest[0] ^= 0x80
	if got := client.Inspect(ctx, url, changed); got != HoldDivergence {
		t.Fatalf("same epoch wrong digest: %s", got)
	}
	foreign := head
	foreign.Vault[0] ^= 1
	if got := client.Inspect(ctx, url, foreign); got != HoldUnavailable {
		t.Fatalf("foreign vault: %s", got)
	}
	closeServer()
	if got := client.Inspect(ctx, url, head); got != HoldUnavailable {
		t.Fatalf("offline owner: %s", got)
	}
}

func TestTLSRequiresPinnedOwnerAndActualMutualAuthentication(t *testing.T) {
	head := fixtureHead(t)
	roots, _, serverCert, clientCert := fixtureCerts(t)
	signerPub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(Handler{Loader: func() (Head, error) { return head, nil },
		SigningKey: signer, ClientSPKIPin: sha256SPKI(clientCert.parsed)})
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert.cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	srv.StartTLS()
	defer srv.Close()
	badPin := [32]byte{88}
	client, err := NewClient(roots, clientCert.cert, badPin, signerPub)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Inspect(context.Background(), srv.URL, head); got != HoldUnavailable {
		t.Fatalf("bad pin: %s", got)
	}
	good, err := NewClient(roots, clientCert.cert, sha256SPKI(serverCert.parsed), []byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if got := good.Inspect(context.Background(), srv.URL, head); got != HoldInvalidWitness {
		t.Fatalf("bad signature key: %s", got)
	}
	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}}
	resp, err := noCert.Post(srv.URL+"/v1/head", "application/json", bytes.NewBufferString("{}"))
	if err == nil {
		resp.Body.Close()
		t.Fatal("unauthenticated TLS connection succeeded")
	}
}

func TestNonceReplayedSignedResponseIsNotFresh(t *testing.T) {
	head := fixtureHead(t)
	roots, _, serverCert, clientCert := fixtureCerts(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var oldNonce [32]byte
	oldNonce[0] = 99
	payload := encode(head, oldNonce)
	replay := signedHead{Payload: payload, Signature: ed25519.Sign(priv, payload)}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(replay)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert.cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	srv.StartTLS()
	defer srv.Close()
	client, err := NewClient(roots, clientCert.cert, sha256SPKI(serverCert.parsed), pub)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.Inspect(context.Background(), srv.URL, head); got != HoldInvalidWitness {
		t.Fatalf("replayed owner response: %s", got)
	}
}

func TestOwnerHeadFileRejectsMissingCorruptionAndWrongType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "head")
	head := fixtureHead(t)
	if _, err := ReadOwnerHead(path); err == nil {
		t.Fatal("missing head accepted")
	}
	writeFixtureHead(t, path, head)
	got, err := ReadOwnerHead(path)
	if err != nil || got != head {
		t.Fatalf("read: %v %v", got, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[24] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOwnerHead(path); err == nil {
		t.Fatal("corrupt head accepted")
	}
	if _, err := ReadOwnerHead(t.TempDir()); err == nil {
		t.Fatal("directory head accepted")
	}
}

// An actual, separately running OS process serves TLS and cold-reopens its
// independent owner head. No network grant or file write is ever issued.
func TestChildOwnerProcess(t *testing.T) {
	if os.Getenv("AKULA_OWNER_CHILD") != "1" {
		return
	}
	decodeEnv := func(k string) []byte {
		b, err := base64.StdEncoding.DecodeString(os.Getenv(k))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM(decodeEnv("AKULA_OWNER_CA")) {
		t.Fatal("bad CA")
	}
	cert, err := tls.X509KeyPair(decodeEnv("AKULA_OWNER_CERT"), decodeEnv("AKULA_OWNER_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	pinRaw := decodeEnv("AKULA_OWNER_CLIENT_PIN")
	var pin [32]byte
	copy(pin[:], pinRaw)
	signer := ed25519.PrivateKey(decodeEnv("AKULA_OWNER_SIGNER"))
	srv := &http.Server{Handler: Handler{Loader: func() (Head, error) { return ReadOwnerHead(os.Getenv("AKULA_OWNER_HEAD")) },
		SigningKey: signer, ClientSPKIPin: pin}, TLSConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca}}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", srv.TLSConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("AKULA_OWNER_READY"), []byte("https://"+listener.Addr().String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := srv.Serve(listener); err != nil {
		t.Fatal(err)
	}
}

func TestSeparateOSOwnerColdRestartRechecksLatestHead(t *testing.T) {
	roots, caPEM, serverCert, clientCert := fixtureCerts(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(roots, clientCert.cert, sha256SPKI(serverCert.parsed), public)
	if err != nil {
		t.Fatal(err)
	}
	head := fixtureHead(t)
	dir := t.TempDir()
	headPath := filepath.Join(dir, "owner-head")
	writeFixtureHead(t, headPath, head)
	env64 := func(k string, b []byte) string { return k + "=" + base64.StdEncoding.EncodeToString(b) }
	start := func() (*exec.Cmd, string) {
		ready := filepath.Join(dir, fmt.Sprintf("ready-%d", time.Now().UnixNano()))
		child := exec.Command(os.Args[0], "-test.run=^TestChildOwnerProcess$")
		child.Env = append(os.Environ(), "AKULA_OWNER_CHILD=1", "AKULA_OWNER_HEAD="+headPath,
			"AKULA_OWNER_READY="+ready, env64("AKULA_OWNER_CA", caPEM), env64("AKULA_OWNER_CERT", serverCert.pemCert),
			env64("AKULA_OWNER_KEY", serverCert.pemKey), env64("AKULA_OWNER_CLIENT_PIN", spkiBytes(clientCert.parsed)),
			env64("AKULA_OWNER_SIGNER", private))
		var logs bytes.Buffer
		child.Stdout = &logs
		child.Stderr = &logs
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			data, err := os.ReadFile(ready)
			if err == nil && strings.HasPrefix(string(data), "https://") {
				return child, string(data)
			}
			if child.ProcessState != nil {
				t.Fatalf("child stopped: %s", logs.String())
			}
			time.Sleep(10 * time.Millisecond)
		}
		child.Process.Kill()
		child.Wait()
		t.Fatalf("owner child not ready: %s", logs.String())
		return nil, ""
	}
	stop := func(child *exec.Cmd) { _ = child.Process.Kill(); _ = child.Wait() }
	child, url := start()
	if got := client.Inspect(context.Background(), url, head); got != ConsistentDenialSnapshotOnly {
		stop(child)
		t.Fatalf("separate process: %s", got)
	}
	stop(child)
	head.Epoch = 2
	nextDigest, err := CanonicalDenyDigest([]Floor{{Replica: [16]byte{7}, Epoch: 2}})
	if err != nil {
		t.Fatal(err)
	}
	head.DenyDigest = nextDigest
	writeFixtureHead(t, headPath, head)
	child, url = start()
	defer stop(child)
	stale := head
	stale.Epoch = 1
	if got := client.Inspect(context.Background(), url, stale); got != HoldJournalBehind {
		t.Fatalf("stale snapshot after owner restart: %s", got)
	}
	if got := client.Inspect(context.Background(), url, head); got != ConsistentDenialSnapshotOnly {
		t.Fatalf("new owner head: %s", got)
	}
}
