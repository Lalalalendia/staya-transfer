package ownerwitness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RN-4E1b-03c1b9 is a DENY-ONLY, research-only gateway. It has no method
// that accepts an arbitrary YDB operation, table, token, or positive grant.
// The gateway process must be operated separately from the untrusted client.
// This boundary alone does NOT defend against a stolen DB writer token or a
// privileged administrator replaying an older valid remote database state.
const gatewayMaxRequestBytes = 2 << 20
const gatewayMaxConcurrent = 4

type ownerDenyGatewayRequest struct {
	Transition SignedDenyTransition `json:"transition"`
	Signature  []byte               `json:"signature"`
}

type OwnerDenyGateway struct {
	gate          *SignedDenyCASGate
	clientSPKIPin [32]byte
	installation  [16]byte
	vault         [16]byte
	slots         chan struct{}
}

// NewOwnerDenyGateway pins one client certificate identity and a separately
// provisioned policy owner key, both independent of the request payload.
// The service process, not an Akula desktop client, supplies the CAS provider.
func NewOwnerDenyGateway(gate *SignedDenyCASGate, clientSPKIPin [32]byte, installation, vault [16]byte) (*OwnerDenyGateway, error) {
	if gate == nil || gate.anchor == nil || len(gate.ownerPublicKey) != ed25519.PublicKeySize ||
		clientSPKIPin == [32]byte{} || installation == [16]byte{} || vault == [16]byte{} {
		return nil, ErrAnchorHold
	}
	return &OwnerDenyGateway{gate: gate, clientSPKIPin: clientSPKIPin, installation: installation, vault: vault,
		slots: make(chan struct{}, gatewayMaxConcurrent)}, nil
}

// ServeHTTP must be mounted behind an actual TLS 1.3 server configured with
// RequireAndVerifyClientCert. A successful response acknowledges ONLY that a
// DENY checkpoint CAS matched, never a permission, receipt or File Gate write.
func (g *OwnerDenyGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if g == nil || g.gate == nil || r == nil {
		http.Error(w, "HOLD", http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/deny/seal" ||
		r.URL.RawQuery != "" || r.URL.Fragment != "" {
		http.Error(w, "HOLD", http.StatusNotFound)
		return
	}
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 ||
		len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 ||
		subtle.ConstantTimeCompare(spkiBytes(r.TLS.PeerCertificates[0]), g.clientSPKIPin[:]) != 1 ||
		r.Header.Get("Authorization") != "" {
		http.Error(w, "HOLD", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" || r.Body == nil {
		http.Error(w, "HOLD", http.StatusBadRequest)
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		http.Error(w, "HOLD", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, gatewayMaxRequestBytes+1))
	if err != nil || len(body) == 0 || len(body) > gatewayMaxRequestBytes {
		http.Error(w, "HOLD", http.StatusBadRequest)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var proposal ownerDenyGatewayRequest
	if decoder.Decode(&proposal) != nil {
		http.Error(w, "HOLD", http.StatusBadRequest)
		return
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || len(proposal.Signature) != ed25519.SignatureSize {
		http.Error(w, "HOLD", http.StatusBadRequest)
		return
	}
	if r.Context().Err() != nil || proposal.Transition.Before.Installation != g.installation ||
		proposal.Transition.Before.Vault != g.vault ||
		proposal.Transition.After.Installation != g.installation ||
		proposal.Transition.After.Vault != g.vault ||
		g.gate.Seal(r.Context(), proposal.Transition, proposal.Signature) != nil {
		http.Error(w, "HOLD", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// OwnerDenyGatewayClient carries only a TLS client certificate, the server
// trust roots and a pinned gateway SPKI. It contains NO IAM token and cannot
// issue generic Document API commands. Response 204 is diagnostic only.
type OwnerDenyGatewayClient struct {
	http       *http.Client
	gatewayPin [32]byte
}

func NewOwnerDenyGatewayClient(roots *x509.CertPool, clientCert tls.Certificate, gatewayPin [32]byte) (*OwnerDenyGatewayClient, error) {
	if roots == nil || len(clientCert.Certificate) == 0 || gatewayPin == [32]byte{} {
		return nil, ErrAnchorHold
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientCert},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 ||
				subtle.ConstantTimeCompare(spkiBytes(state.PeerCertificates[0]), gatewayPin[:]) != 1 {
				return errors.New("unexpected gateway SPKI")
			}
			return nil
		},
	}, DisableCompression: true}
	return &OwnerDenyGatewayClient{http: &http.Client{Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }},
		gatewayPin: gatewayPin}, nil
}

func validGatewayEndpoint(base string) bool {
	u, err := url.Parse(base)
	return err == nil && u.Scheme == "https" && u.Host != "" &&
		u.User == nil && u.RawQuery == "" && u.Fragment == "" &&
		u.RawPath == "" && u.Path == "" &&
		!strings.HasSuffix(base, "/")
}

func (c *OwnerDenyGatewayClient) SubmitDeny(ctx context.Context, baseURL string, transition SignedDenyTransition, signature []byte) error {
	if c == nil || c.http == nil || ctx == nil || ctx.Err() != nil ||
		!validGatewayEndpoint(baseURL) || len(signature) != ed25519.SignatureSize {
		return ErrAnchorHold
	}
	body, err := json.Marshal(ownerDenyGatewayRequest{Transition: transition, Signature: signature})
	if err != nil || len(body) > gatewayMaxRequestBytes {
		return ErrAnchorHold
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/deny/seal", bytes.NewReader(body))
	if err != nil {
		return ErrAnchorHold
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil || ctx.Err() != nil {
		return ErrAnchorHold
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent || ctx.Err() != nil {
		return ErrAnchorHold
	}
	// A 204 has no payload or credentials. Reject any noncanonical body if a
	// nonstandard intermediary tries to inject extra success information.
	one := make([]byte, 1)
	n, err := res.Body.Read(one)
	if n != 0 || err != io.EOF {
		return ErrAnchorHold
	}
	return nil
}
