package ownerwitness

import (
	"bytes"
	"context"
	"net/url"
	"strings"
)

// RemoteDenialPeer is an independently authenticated, read-only witness.
// A real deployment requires two different operators, key custody domains,
// machines and backing storage. Distinct TLS/signing keys alone do not prove
// independent administration. The client cannot cause either remote to seal.
type RemoteDenialPeer struct {
	BaseURL string
	Client  *Client
}

// ReadOnlyRemoteQuorum requires an exact 2-of-2 match of independent signed
// online witnesses. If either endpoint is unreachable, lying, behind, ahead,
// signing with an unknown key or inconsistent, it returns HOLD. It is a
// DenialAnchorReader, NOT a TrustedDenialAnchor; the owner cannot accidentally
// append a journal record before receiving a read-only seal rejection.
type ReadOnlyRemoteQuorum struct {
	first, second RemoteDenialPeer
}

var _ DenialAnchorReader = (*ReadOnlyRemoteQuorum)(nil)

func validateRemotePeer(p RemoteDenialPeer) error {
	if p.Client == nil || p.Client.http == nil || len(p.Client.signingKey) != 32 ||
		p.Client.tlsPin == [32]byte{} {
		return ErrAnchorHold
	}
	u, err := url.Parse(p.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") ||
		strings.HasSuffix(p.BaseURL, "/") {
		return ErrAnchorHold
	}
	return nil
}

func NewReadOnlyRemoteQuorum(a, b RemoteDenialPeer) (*ReadOnlyRemoteQuorum, error) {
	if validateRemotePeer(a) != nil || validateRemotePeer(b) != nil ||
		a.BaseURL == b.BaseURL ||
		a.Client.tlsPin == b.Client.tlsPin ||
		bytes.Equal(a.Client.signingKey, b.Client.signingKey) {
		return nil, ErrAnchorHold
	}
	return &ReadOnlyRemoteQuorum{first: a, second: b}, nil
}

// Read performs two FRESH authenticated network reads for the same namespace.
// It deliberately has no successful offline mode or cached fallback; equal
// but stale replies from TWO colluding/rolled-back witnesses remain a limit.
func (q *ReadOnlyRemoteQuorum) Read(ctx context.Context, installation, vault [16]byte) (DenialCheckpoint, error) {
	if q == nil || ctx == nil || ctx.Err() != nil || installation == [16]byte{} || vault == [16]byte{} {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	type response struct {
		head    Head
		verdict Verdict
	}
	results := make(chan response, 2)
	for _, peer := range []RemoteDenialPeer{q.first, q.second} {
		p := peer
		go func() {
			head, verdict := p.Client.FetchHead(ctx, p.BaseURL, installation, vault)
			results <- response{head: head, verdict: verdict}
		}()
	}
	var a, b response
	// Both clients have their own three-second timeout. No partial success.
	select {
	case a = <-results:
	case <-ctx.Done():
		return DenialCheckpoint{}, ErrAnchorHold
	}
	select {
	case b = <-results:
	case <-ctx.Done():
		return DenialCheckpoint{}, ErrAnchorHold
	}
	if ctx.Err() != nil || a.verdict != ConsistentDenialSnapshotOnly || b.verdict != ConsistentDenialSnapshotOnly ||
		a.head != b.head {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	checkpoint, err := checkpointFor(a.head)
	if err != nil || checkpoint.Installation != installation || checkpoint.Vault != vault {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	return checkpoint, nil
}

// Compile-time authority separation: there is intentionally no CompareAndSeal
// method on *ReadOnlyRemoteQuorum, so this reader cannot be used for writes.
