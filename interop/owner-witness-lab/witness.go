// Package ownerwitness is an isolated protocol research lab. It cannot issue
// grants, receipts, APPLIED or filesystem permissions. An authenticated,
// independently operated owner must be online for every consistency check.
package ownerwitness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"
)

const domain = "AKULA_OWNER_WITNESS_V1\x00"
const mapDomain = "AKULA_DENY_FLOORS_V1\x00"
const payloadSize = len(domain) + 16 + 16 + 8 + 32 + 32
const maxHTTPBody = 2048

type Head struct {
	Installation [16]byte
	Vault        [16]byte
	Epoch        uint64
	DenyDigest   [32]byte
}

type Floor struct {
	Replica [16]byte
	Epoch   uint64
}

// CanonicalDenyDigest commits to the FULL sorted deny-floor map, not just the
// total epoch. This is not a digest of a future positive-grant policy.
func CanonicalDenyDigest(floors []Floor) ([32]byte, error) {
	if len(floors) > 4096 {
		return [32]byte{}, errors.New("too many replicas")
	}
	sorted := append([]Floor(nil), floors...)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].Replica[:], sorted[j].Replica[:]) < 0
	})
	h := sha256.New()
	h.Write([]byte(mapDomain))
	var word [8]byte
	binary.LittleEndian.PutUint32(word[:4], uint32(len(sorted)))
	h.Write(word[:4])
	for i, f := range sorted {
		if f.Replica == [16]byte{} || f.Epoch == 0 || (i > 0 && f.Replica == sorted[i-1].Replica) {
			return [32]byte{}, errors.New("invalid or duplicate replica floor")
		}
		h.Write(f.Replica[:])
		binary.LittleEndian.PutUint64(word[:], f.Epoch)
		h.Write(word[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func validHead(head Head) bool {
	return head.Installation != [16]byte{} && head.Vault != [16]byte{} &&
		head.DenyDigest != [32]byte{}
}

func encode(head Head, nonce [32]byte) []byte {
	b := make([]byte, 0, payloadSize)
	b = append(b, domain...)
	b = append(b, head.Installation[:]...)
	b = append(b, head.Vault[:]...)
	var epoch [8]byte
	binary.LittleEndian.PutUint64(epoch[:], head.Epoch)
	b = append(b, epoch[:]...)
	b = append(b, head.DenyDigest[:]...)
	b = append(b, nonce[:]...)
	return b
}

func decode(payload []byte) (Head, [32]byte, error) {
	var head Head
	var nonce [32]byte
	if len(payload) != payloadSize || !bytes.Equal(payload[:len(domain)], []byte(domain)) {
		return head, nonce, errors.New("noncanonical witness frame")
	}
	b := payload[len(domain):]
	copy(head.Installation[:], b[:16])
	b = b[16:]
	copy(head.Vault[:], b[:16])
	b = b[16:]
	head.Epoch = binary.LittleEndian.Uint64(b[:8])
	b = b[8:]
	copy(head.DenyDigest[:], b[:32])
	b = b[32:]
	copy(nonce[:], b[:32])
	if !validHead(head) || nonce == [32]byte{} {
		return Head{}, [32]byte{}, errors.New("zero identity, digest or nonce")
	}
	return head, nonce, nil
}

type headRequest struct {
	Installation string `json:"installation"`
	Vault        string `json:"vault"`
	Nonce        []byte `json:"nonce"`
}

type signedHead struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// Handler never accepts a state mutation from the network. A separate trusted
// owner service must provision and persist the latest head; the Loader must
// fail if that storage cannot be trusted or read.
type Handler struct {
	Loader        func() (Head, error)
	SigningKey    ed25519.PrivateKey
	ClientSPKIPin [32]byte
}

func readExactlyJSON(r io.Reader, value any) error {
	decoder := json.NewDecoder(io.LimitReader(r, maxHTTPBody+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var additional any
	if decoder.Decode(&additional) != io.EOF {
		return errors.New("trailing or overlong JSON")
	}
	return nil
}

func (s Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/head" || r.Method != http.MethodPost {
		http.Error(w, "unsupported", http.StatusNotFound)
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 ||
		subtle.ConstantTimeCompare(spkiBytes(r.TLS.PeerCertificates[0]), s.ClientSPKIPin[:]) != 1 {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	if len(s.SigningKey) != ed25519.PrivateKeySize || s.Loader == nil {
		http.Error(w, "owner unavailable", http.StatusServiceUnavailable)
		return
	}
	var req headRequest
	if readExactlyJSON(r.Body, &req) != nil || len(req.Nonce) != 32 {
		http.Error(w, "invalid challenge", http.StatusBadRequest)
		return
	}
	var nonce [32]byte
	copy(nonce[:], req.Nonce)
	if nonce == [32]byte{} {
		http.Error(w, "zero challenge", http.StatusBadRequest)
		return
	}
	h, err := s.Loader()
	if err != nil || !validHead(h) {
		http.Error(w, "trusted head unavailable", http.StatusServiceUnavailable)
		return
	}
	if req.Installation != hex.EncodeToString(h.Installation[:]) || req.Vault != hex.EncodeToString(h.Vault[:]) {
		http.Error(w, "unknown namespace", http.StatusConflict)
		return
	}
	payload := encode(h, nonce)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(signedHead{Payload: payload, Signature: ed25519.Sign(s.SigningKey, payload)})
}

func sha256SPKI(cert *x509.Certificate) [32]byte { return sha256.Sum256(cert.RawSubjectPublicKeyInfo) }
func spkiBytes(cert *x509.Certificate) []byte    { pin := sha256SPKI(cert); return pin[:] }

// NewClient requires both standard TLS chain/hostname verification and an
// independent pinned owner TLS leaf SPKI, plus the owner's signing public key.
// No InsecureSkipVerify or unauthenticated fallback exists.
func NewClient(roots *x509.CertPool, clientCert tls.Certificate, serverSPKIPin [32]byte, ownerSignKey ed25519.PublicKey) (*Client, error) {
	if roots == nil || len(ownerSignKey) != ed25519.PublicKeySize || serverSPKIPin == [32]byte{} || len(clientCert.Certificate) == 0 {
		return nil, errors.New("missing pinned trust anchor")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientCert},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || subtle.ConstantTimeCompare(spkiBytes(state.PeerCertificates[0]), serverSPKIPin[:]) != 1 {
				return errors.New("wrong owner TLS SPKI")
			}
			return nil
		},
	}}
	return &Client{http: &http.Client{Transport: transport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect prohibited") }},
		signingKey: append(ed25519.PublicKey(nil), ownerSignKey...)}, nil
}

type Client struct {
	http       *http.Client
	signingKey ed25519.PublicKey
}
type Verdict string

const (
	HoldUnavailable              Verdict = "HOLD_UNAVAILABLE"
	HoldInvalidWitness           Verdict = "HOLD_INVALID_WITNESS"
	HoldJournalBehind            Verdict = "HOLD_LOCAL_BEHIND"
	HoldJournalAhead             Verdict = "HOLD_LOCAL_AHEAD"
	HoldDivergence               Verdict = "HOLD_DIVERGENCE"
	ConsistentDenialSnapshotOnly Verdict = "CONSISTENT_DENIAL_ONLY"
)

// Inspect does not return a grant even if local bytes and remote head match.
// The caller must not cache an earlier successful result as authorization.
func (c *Client) Inspect(ctx context.Context, url string, local Head) Verdict {
	if c == nil || c.http == nil || !validHead(local) {
		return HoldInvalidWitness
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return HoldUnavailable
	}
	request, _ := json.Marshal(headRequest{
		Installation: hex.EncodeToString(local.Installation[:]),
		Vault:        hex.EncodeToString(local.Vault[:]), Nonce: nonce[:],
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/v1/head", bytes.NewReader(request))
	if err != nil {
		return HoldUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return HoldUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return HoldUnavailable
	}
	var signed signedHead
	if readExactlyJSON(res.Body, &signed) != nil || len(signed.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(c.signingKey, signed.Payload, signed.Signature) {
		return HoldInvalidWitness
	}
	remote, gotNonce, err := decode(signed.Payload)
	if err != nil || subtle.ConstantTimeCompare(gotNonce[:], nonce[:]) != 1 ||
		remote.Installation != local.Installation || remote.Vault != local.Vault {
		return HoldInvalidWitness
	}
	if local.Epoch < remote.Epoch {
		return HoldJournalBehind
	}
	if local.Epoch > remote.Epoch {
		return HoldJournalAhead
	}
	if local.DenyDigest != remote.DenyDigest {
		return HoldDivergence
	}
	return ConsistentDenialSnapshotOnly
}
