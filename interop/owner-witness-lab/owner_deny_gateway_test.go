package ownerwitness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freshDenyTransition(t *testing.T) (SignedDenyTransition, ed25519.PublicKey, []byte) {
	t.Helper()
	transition := signedTransitionFixture(t, nil, []Floor{{Replica: testLedgerReplica, Epoch: 1}}, 0, testLedgerReplica)
	pub, signature := signTransition(t, transition)
	return transition, pub, signature
}

func gatewayTestServer(t *testing.T, tr SignedDenyTransition, pub ed25519.PublicKey) (string, *OwnerDenyGatewayClient, *documentAPIFixture, *httptest.Server, *tls.Config) {
	t.Helper()
	provider, f := newYDBFixture(t, Head{Installation: tr.Before.Installation,
		Vault: tr.Before.Vault, Epoch: tr.Before.Epoch, DenyDigest: tr.Before.DenyDigest})
	gate, err := NewSignedDenyCASGate(pub, provider)
	if err != nil {
		t.Fatal(err)
	}
	roots, _, serverCert, clientCert := fixtureCerts(t)
	gateway, err := NewOwnerDenyGateway(gate, sha256SPKI(clientCert.parsed), tr.Before.Installation, tr.Before.Vault)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(gateway)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert.cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	client, err := NewOwnerDenyGatewayClient(roots, clientCert.cert, sha256SPKI(serverCert.parsed))
	if err != nil {
		t.Fatal(err)
	}
	return srv.URL, client, f, srv, srv.TLS
}

func TestOwnerDenyGatewayMutualTLSBoundedAndNoIAMCredentialLeak(t *testing.T) {
	transition, pub, sig := freshDenyTransition(t)
	baseURL, client, backend, _, _ := gatewayTestServer(t, transition, pub)
	ctx := context.Background()
	if err := client.SubmitDeny(ctx, baseURL, transition, sig); err != nil {
		t.Fatalf("genuine signed revoke refused over TLS: %v", err)
	}
	backend.mu.Lock()
	updates, reads, after := backend.totalUpdate, backend.totalGet, backend.row["Epoch"]
	backend.mu.Unlock()
	if updates != 1 || reads < 2 || after.N == nil || *after.N != "1" {
		t.Fatalf("not exactly one YDB CAS: updates=%d reads=%d epoch=%+v", updates, reads, after)
	}
	if err := client.SubmitDeny(ctx, baseURL, transition, sig); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("replayed owner signature accepted: %v", err)
	}
	backend.mu.Lock()
	updates = backend.totalUpdate
	backend.mu.Unlock()
	if updates != 1 {
		t.Fatal("replay invoked conditional UpdateItem again")
	}
	// The client is capability-limited: it has no IAMTokenSource or DB URL.
	if _, ok := any(client).(TrustedDenialAnchor); ok {
		t.Fatal("network client acquired remote writer credentials/interface")
	}
}

func rawDenyRequest(t *testing.T, client *OwnerDenyGatewayClient, method, url, body string, headers map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 256))
	return res.StatusCode
}

func TestOwnerDenyGatewayRejectsInvalidCallerAndNonProtocolRequestsBeforeYDB(t *testing.T) {
	transition, pub, sig := freshDenyTransition(t)
	base, client, backend, _, _ := gatewayTestServer(t, transition, pub)
	proposal, _ := json.Marshal(ownerDenyGatewayRequest{Transition: transition, Signature: sig})
	good := string(proposal)
	cases := []struct {
		method string
		path   string
		body   string
		head   map[string]string
	}{
		{"GET", "/v1/deny/seal", good, map[string]string{"Content-Type": "application/json"}},
		{"POST", "/v1/head", good, map[string]string{"Content-Type": "application/json"}},
		{"POST", "/v1/deny/seal?table=evil", good, map[string]string{"Content-Type": "application/json"}},
		{"POST", "/v1/deny/seal", good, map[string]string{"Content-Type": "text/plain"}},
		{"POST", "/v1/deny/seal", good, map[string]string{"Content-Type": "application/json", "Authorization": "Bearer leaked-iam"}},
		{"POST", "/v1/deny/seal", `{"unknown":"proxy"}`, map[string]string{"Content-Type": "application/json"}},
		{"POST", "/v1/deny/seal", good + `{"extra":1}`, map[string]string{"Content-Type": "application/json"}},
		{"POST", "/v1/deny/seal", `{"transition":{},"signature":"!"}`, map[string]string{"Content-Type": "application/json"}},
	}
	for i, c := range cases {
		status := rawDenyRequest(t, client, c.method, base+c.path, c.body, c.head)
		if status == http.StatusNoContent || status == http.StatusOK {
			t.Fatalf("non-protocol request %d passed: %d", i, status)
		}
	}
	oversize := strings.Repeat("x", gatewayMaxRequestBytes+1)
	if status := rawDenyRequest(t, client, "POST", base+"/v1/deny/seal", oversize, map[string]string{"Content-Type": "application/json"}); status == http.StatusNoContent {
		t.Fatal("overlong request allowed")
	}
	backend.mu.Lock()
	gets, writes := backend.totalGet, backend.totalUpdate
	backend.mu.Unlock()
	if gets != 0 || writes != 0 {
		t.Fatalf("unauthorized HTTP reached YDB: reads=%d writes=%d", gets, writes)
	}
}

func TestOwnerDenyGatewayMutualAuthenticationSignatureAndPinAreRequired(t *testing.T) {
	transition, pub, signature := freshDenyTransition(t)
	base, client, backend, _, srvTLS := gatewayTestServer(t, transition, pub)
	badSignature := append([]byte(nil), signature...)
	badSignature[0] ^= 1
	if err := client.SubmitDeny(context.Background(), base, transition, badSignature); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("invalid owner signature not rejected")
	}
	if err := client.SubmitDeny(context.Background(), "http://127.0.0.1:1234", transition, signature); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("unencrypted gateway accepted")
	}
	if err := client.SubmitDeny(context.Background(), base+"/", transition, signature); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("noncanonical base URL accepted")
	}
	bad := *client
	bad.http = &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: client.http.Transport.(*http.Transport).TLSClientConfig.Certificates,
		RootCAs:          client.http.Transport.(*http.Transport).TLSClientConfig.RootCAs,
		VerifyConnection: func(tls.ConnectionState) error { return errors.New("wrong pinned gateway") },
	}}}
	if err := bad.SubmitDeny(context.Background(), base, transition, signature); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("wrong pinned server TLS identity accepted")
	}
	// A client without a certificate cannot complete the server TLS handshake.
	noCert := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: client.http.Transport.(*http.Transport).TLSClientConfig.RootCAs,
	}}}
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/deny/seal", bytes.NewReader(nil))
	resp, err := noCert.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("anonymous client unexpectedly passed TLS")
	}
	if srvTLS.MinVersion != tls.VersionTLS13 || srvTLS.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("server fixture does not exercise mutual TLS 1.3")
	}
	backend.mu.Lock()
	gets, updates := backend.totalGet, backend.totalUpdate
	backend.mu.Unlock()
	if gets != 0 || updates != 0 {
		t.Fatal("bad signature or transport contacted YDB")
	}
}

// This helper is invoked only as a separate test-binary process. Its state is
// an in-memory test double, NOT a durable owner or a real cloud installation.
func TestOwnerDenyGatewayChildProcess(t *testing.T) {
	dir := os.Getenv("AKULA_GATEWAY_TEST_HELPER_DIR")
	if dir == "" {
		return
	}
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	serverCert, err := tls.X509KeyPair(read("server.pem"), read("server.key"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(read("ca.pem")) {
		t.Fatal("invalid disposable CA")
	}
	pinBytes, err := hex.DecodeString(strings.TrimSpace(string(read("client.pin"))))
	if err != nil || len(pinBytes) != 32 {
		t.Fatal("invalid test pin")
	}
	var pin [32]byte
	copy(pin[:], pinBytes)
	pub := ed25519.PublicKey(read("owner.pub"))
	var cp DenialCheckpoint
	if err := json.Unmarshal(read("checkpoint.json"), &cp); err != nil {
		t.Fatal(err)
	}
	anchor := &memoryAnchor{stamp: cp}
	gate, err := NewSignedDenyCASGate(pub, anchor)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewOwnerDenyGateway(gate, pin, cp.Installation, cp.Vault)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	if err := os.WriteFile(filepath.Join(dir, "url"), []byte(srv.URL), 0600); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
	srv.Close()
}

func TestOwnerDenyGatewayReallySeparateOSProcess(t *testing.T) {
	tr, pub, sig := freshDenyTransition(t)
	roots, caPEM, serverCert, clientCert := fixtureCerts(t)
	dir := t.TempDir()
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("server.pem", serverCert.pemCert)
	write("server.key", serverCert.pemKey)
	write("ca.pem", caPEM)
	pin := sha256SPKI(clientCert.parsed)
	write("client.pin", []byte(hex.EncodeToString(pin[:])))
	write("owner.pub", pub)
	cp, _ := checkpointFor(Head{Installation: tr.Before.Installation, Vault: tr.Before.Vault,
		Epoch: tr.Before.Epoch, DenyDigest: tr.Before.DenyDigest})
	encoded, _ := json.Marshal(cp)
	write("checkpoint.json", encoded)

	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnerDenyGatewayChildProcess$")
	cmd.Env = append(os.Environ(), "AKULA_GATEWAY_TEST_HELPER_DIR="+dir)
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	var endpoint string
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(filepath.Join(dir, "url"))
		if err == nil && strings.HasPrefix(string(data), "https://127.0.0.1:") {
			endpoint = string(data)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if endpoint == "" {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("gateway child did not bind TLS: %s", logs.String())
	}
	client, err := NewOwnerDenyGatewayClient(roots, clientCert.cert, sha256SPKI(serverCert.parsed))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SubmitDeny(context.Background(), endpoint, tr, sig); err != nil {
		t.Fatalf("independent gateway process rejected signed transition: %v; child=%s", err, logs.String())
	}
	if err := client.SubmitDeny(context.Background(), endpoint, tr, sig); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("OS-process gateway replay accepted")
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("gateway subprocess did not exit cleanly: %v logs=%s", err, logs.String())
	}
}

func TestOwnerDenyGatewayRejectsCorrectlySignedForeignNamespaceBeforeYDB(t *testing.T) {
	tr, _, _ := freshDenyTransition(t)
	pub, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base, client, backend, _, _ := gatewayTestServer(t, tr, pub)
	foreign := tr
	foreign.Before.Vault[0] ^= 0x40
	foreign.After.Vault[0] ^= 0x40
	foreign.Before, err = checkpointFor(Head{Installation: foreign.Before.Installation,
		Vault: foreign.Before.Vault, Epoch: foreign.Before.Epoch, DenyDigest: foreign.Before.DenyDigest})
	if err != nil {
		t.Fatal(err)
	}
	foreign.After, err = checkpointFor(Head{Installation: foreign.After.Installation,
		Vault: foreign.After.Vault, Epoch: foreign.After.Epoch, DenyDigest: foreign.After.DenyDigest})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDenyTransition(foreign); err != nil {
		t.Fatal(err)
	}
	signed := ed25519.Sign(signer, signedTransitionBytes(foreign))
	if err := client.SubmitDeny(context.Background(), base, foreign, signed); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("validly signed transition escaped gateway namespace binding")
	}
	backend.mu.Lock()
	reads, writes := backend.totalGet, backend.totalUpdate
	backend.mu.Unlock()
	if reads != 0 || writes != 0 {
		t.Fatalf("foreign vault contacted YDB: reads=%d writes=%d", reads, writes)
	}
}

func TestOwnerDenyGatewayMissingCredentialsAndCancelledRequests(t *testing.T) {
	tr, pub, sig := freshDenyTransition(t)
	provider := freshMemoryAnchor(t, Head{Installation: tr.Before.Installation, Vault: tr.Before.Vault,
		Epoch: tr.Before.Epoch, DenyDigest: tr.Before.DenyDigest})
	gate, err := NewSignedDenyCASGate(pub, provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewOwnerDenyGateway(gate, [32]byte{}, tr.Before.Installation, tr.Before.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("missing pinned identity accepted")
	}
	if _, err := NewOwnerDenyGateway(gate, [32]byte{1}, [16]byte{}, tr.Before.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("unbound tenant identity accepted")
	}
	if _, err := NewOwnerDenyGateway(nil, [32]byte{1}, tr.Before.Installation, tr.Before.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("missing signing authority accepted")
	}
	if _, err := NewOwnerDenyGatewayClient(nil, tls.Certificate{}, [32]byte{1}); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("missing TLS roots accepted")
	}
	base, client, backend, _, _ := gatewayTestServer(t, tr, pub)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.SubmitDeny(ctx, base, tr, sig); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("cancelled request was accepted")
	}
	backend.mu.Lock()
	reads, writes := backend.totalGet, backend.totalUpdate
	backend.mu.Unlock()
	if reads != 0 || writes != 0 {
		t.Fatal("cancelled request touched remote backend")
	}
	// No path to YDB credentials or arbitrary requests exists on the client.
}
