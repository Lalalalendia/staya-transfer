package ownerwitness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func makeWORMVersion(t *testing.T, c DenialCheckpoint, previous [32]byte, private ed25519.PrivateKey, id string, isLatest bool, until time.Time) (LockedWORMVersion, [32]byte) {
	t.Helper()
	message := wormSignaturePayload(c, previous)
	signature := ed25519.Sign(private, message)
	digest := append(append([]byte(nil), message...), signature...)
	hash := sha256Sum(digest)
	payload, err := json.Marshal(wormSignedRecord{
		Schema:       wormSchema,
		Installation: hex.EncodeToString(c.Installation[:]), Vault: hex.EncodeToString(c.Vault[:]),
		Epoch: strconvUint(c.Epoch), DenyDigest: hex.EncodeToString(c.DenyDigest[:]),
		Commitment: hex.EncodeToString(c.Commitment[:]), Previous: hex.EncodeToString(previous[:]),
		Signature: base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return LockedWORMVersion{ID: id, Latest: isLatest, Mode: "COMPLIANCE", RetainUntil: until, Payload: payload}, hash
}
func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
func strconvUint(n uint64) string { return strconv.FormatUint(n, 10) }

func wormFixture(t *testing.T) (ed25519.PublicKey, []LockedWORMVersion, DenialCheckpoint, DenialCheckpoint, time.Time) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	empty, err := CanonicalDenyDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	newDigest, err := CanonicalDenyDigest([]Floor{{Replica: [16]byte{91}, Epoch: 1}})
	if err != nil {
		t.Fatal(err)
	}
	inst := [16]byte{1}
	vault := [16]byte{2}
	old, err := checkpointFor(Head{Installation: inst, Vault: vault, Epoch: 0, DenyDigest: empty})
	if err != nil {
		t.Fatal(err)
	}
	next, err := checkpointFor(Head{Installation: inst, Vault: vault, Epoch: 1, DenyDigest: newDigest})
	if err != nil {
		t.Fatal(err)
	}
	first, hash := makeWORMVersion(t, old, [32]byte{}, private, "version-0", false, now.Add(300*24*time.Hour))
	second, _ := makeWORMVersion(t, next, hash, private, "version-1", true, now.Add(300*24*time.Hour))
	return public, []LockedWORMVersion{second, first}, old, next, now
}

func TestWORMCompleteComplianceHistoryMatchesCurrentYDB(t *testing.T) {
	pub, versions, old, next, now := wormFixture(t)
	actual, err := InspectWORMVersions(versions, pub, next.Installation, next.Vault, now, 7*24*time.Hour)
	if err != nil || actual != next {
		t.Fatalf("expected one trustworthy observed chain: %v %+v", err, actual)
	}
	if err := ObserveYDBAgainstWORM(versions, pub, next, now, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	// A privileged administrator restores a perfectly valid older YDB row.
	// The retained S3 epoch=1 version remains visible and refuses it.
	if err := ObserveYDBAgainstWORM(versions, pub, old, now, 7*24*time.Hour); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("old YDB accepted: %v", err)
	}
}

func TestWORMVersionsTamperAndExpiringRetentionAreHold(t *testing.T) {
	pub, versions, _, next, now := wormFixture(t)
	cases := []struct {
		name   string
		change func([]LockedWORMVersion) []LockedWORMVersion
	}{
		{"governance-mode", func(v []LockedWORMVersion) []LockedWORMVersion { v[0].Mode = "GOVERNANCE"; return v }},
		{"not-enough-retention", func(v []LockedWORMVersion) []LockedWORMVersion {
			v[0].RetainUntil = now.Add(5 * 24 * time.Hour)
			return v
		}},
		{"missing-genesis", func(v []LockedWORMVersion) []LockedWORMVersion { return v[:1] }},
		{"duplicate-last-record", func(v []LockedWORMVersion) []LockedWORMVersion {
			last := v[0]
			last.ID = "unprotected-copy"
			last.Latest = false
			return append(v, last)
		}},
		{"duplicated-version-id", func(v []LockedWORMVersion) []LockedWORMVersion { v[0].ID = v[1].ID; return v }},
		{"missing-latest-marker", func(v []LockedWORMVersion) []LockedWORMVersion { v[0].Latest = false; return v }},
		{"latest-points-to-old-epoch", func(v []LockedWORMVersion) []LockedWORMVersion { v[0].Latest = false; v[1].Latest = true; return v }},
		{"different-owner-signature", func(v []LockedWORMVersion) []LockedWORMVersion {
			v[0].Payload = append([]byte(nil), v[1].Payload...)
			return v
		}},
		{"trailing-json", func(v []LockedWORMVersion) []LockedWORMVersion {
			v[0].Payload = append(v[0].Payload, []byte("{}")...)
			return v
		}},
		{"oversized-object", func(v []LockedWORMVersion) []LockedWORMVersion {
			v[0].Payload = []byte(strings.Repeat("x", wormMaxObjectBytes+1))
			return v
		}},
		{"zero-retention-date", func(v []LockedWORMVersion) []LockedWORMVersion { v[0].RetainUntil = time.Time{}; return v }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vv := append([]LockedWORMVersion(nil), versions...)
			vv = c.change(vv)
			if err := ObserveYDBAgainstWORM(vv, pub, next, now, 7*24*time.Hour); !errors.Is(err, ErrAnchorHold) {
				t.Fatalf("invalid history accepted: %v", err)
			}
		})
	}
}

func TestWORMForkBrokenHashChainAndDuplicateEpochAreHold(t *testing.T) {
	pub, versions, _, next, now := wormFixture(t)
	// A malicious uploader has a signing key for a different record, but
	// its 'previous' does not reference the immutable genesis record.
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fork, _ := makeWORMVersion(t, next, [32]byte{}, other, "fork", true, now.Add(300*24*time.Hour))
	for _, vv := range [][]LockedWORMVersion{
		{fork, versions[1]},
		{versions[0], versions[0], versions[1]},
	} {
		if err := ObserveYDBAgainstWORM(vv, pub, next, now, 7*24*time.Hour); !errors.Is(err, ErrAnchorHold) {
			t.Fatal("broken chain passed")
		}
	}
}

// Compliance locks expire. If all later locked versions were legally removed
// after retention, a remaining old genesis can look internally consistent.
// This negative test proves an independent pinned last-known high-water (or
// retention covering the entire threat horizon) is STILL mandatory.
func TestWORMExpiredTailDeletionRemainsReleaseBlocker(t *testing.T) {
	pub, versions, old, _, now := wormFixture(t)
	genesis := versions[1]
	genesis.Latest = true
	observed, err := InspectWORMVersions([]LockedWORMVersion{genesis}, pub, old.Installation, old.Vault, now, 7*24*time.Hour)
	if err != nil || observed != old {
		t.Fatalf("missing-tail limitation no longer demonstrated: %v", err)
	}
}

func TestWORMVersionCountAndInvalidInputFailClosed(t *testing.T) {
	pub, versions, _, next, now := wormFixture(t)
	inflated := make([]LockedWORMVersion, wormMaxVersions+1)
	if _, err := InspectWORMVersions(inflated, pub, next.Installation, next.Vault, now, 7*24*time.Hour); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("unbounded history passed")
	}
	if _, err := InspectWORMVersions(versions, pub, next.Installation, [16]byte{99}, now, 7*24*time.Hour); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("other tenant passed")
	}
	if _, err := InspectWORMVersions(versions, pub, next.Installation, next.Vault, now, 0); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("no retention horizon passed")
	}
	if _, err := InspectWORMVersions(versions, pub, next.Installation, next.Vault, now, 400*24*time.Hour); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("unsupported retention horizon passed")
	}
	if err := RunReadOnlyWORMPreflight(context.Background(), ReadOnlyObjectLockPreflight{Bucket: "bad bucket", Key: "x"}, pub, next, now); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("invalid bucket passed")
	}
}

// This is a real read-only Yandex Object Storage probe when (and only when)
// the operator has separately provisioned bucket, policy owner and IAM role.
// The test prints SKIP in CI without cloud credentials, never a fake PASS.
func TestObjectLockLiveReadOnlyPreflight(t *testing.T) {
	if os.Getenv("STY_WORM_LIVE_READ") != "1" {
		t.Skip("requires independently provisioned bucket and read-only operator credentials")
	}
	bucket := os.Getenv("STY_WORM_BUCKET")
	key := os.Getenv("STY_WORM_KEY")
	pubRaw, err := hex.DecodeString(os.Getenv("STY_WORM_OWNER_PUBLIC_KEY_HEX"))
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		t.Fatal("invalid pinned owner signing key")
	}
	ins, errI := hex.DecodeString(os.Getenv("STY_WORM_INSTALLATION_HEX"))
	vault, errV := hex.DecodeString(os.Getenv("STY_WORM_VAULT_HEX"))
	digest, errD := hex.DecodeString(os.Getenv("STY_WORM_DENY_DIGEST_HEX"))
	if errI != nil || errV != nil || errD != nil || len(ins) != 16 || len(vault) != 16 || len(digest) != 32 {
		t.Fatal("invalid namespace/digest")
	}
	epoch, err := strconv.ParseUint(os.Getenv("STY_WORM_EXPECTED_EPOCH"), 10, 64)
	if err != nil || strconv.FormatUint(epoch, 10) != os.Getenv("STY_WORM_EXPECTED_EPOCH") {
		t.Fatal("invalid epoch")
	}
	var installation, vaultID [16]byte
	var h [32]byte
	copy(installation[:], ins)
	copy(vaultID[:], vault)
	copy(h[:], digest)
	cp, err := checkpointFor(Head{Installation: installation, Vault: vaultID, Epoch: epoch, DenyDigest: h})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	source := ReadOnlyObjectLockPreflight{Bucket: bucket, Key: key}
	if err := RunReadOnlyWORMPreflight(ctx, source, ed25519.PublicKey(pubRaw), cp, time.Now()); err != nil {
		t.Fatalf("READ-ONLY Object Lock preflight: HOLD: %v", err)
	}
}

func TestReadOnlyS3AWSCliCommandAllowlistOnLinux(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mock command is not available on Windows")
	}
	pub, versions, _, next, now := wormFixture(t)
	root := t.TempDir()
	// A disposable executable simulates the AWS CLI and logs verbs only.
	// The production adapter must never issue put/delete or expose a secret.
	var sourceBytes []byte
	sourceBytes = versions[0].Payload
	if err := os.WriteFile(filepath.Join(root, "v1.json"), sourceBytes, 0600); err != nil {
		t.Fatal(err)
	}
	sourceBytes = versions[1].Payload
	if err := os.WriteFile(filepath.Join(root, "v0.json"), sourceBytes, 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$STY_FAKE_AWS_LOG"
case "$*" in
*get-bucket-versioning*) echo '{"Status":"Enabled"}' ;;
*get-object-lock-configuration*) echo '{"ObjectLockConfiguration":{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":300}}}}' ;;
*list-object-versions*) echo '{"Versions":[{"Key":"audit/revocation.json","VersionId":"v1","IsLatest":true,"Size":440},{"Key":"audit/revocation.json","VersionId":"v0","IsLatest":false,"Size":440}]}' ;;
*get-object-retention*) echo '{"Retention":{"Mode":"COMPLIANCE","RetainUntilDate":"2027-08-20T12:00:00Z"}}' ;;
*get-object*)
    eval "out=\${$#}"
    case "$*" in *v1*) cp "$STY_FAKE_AWS_ROOT/v1.json" "$out" ;; *v0*) cp "$STY_FAKE_AWS_ROOT/v0.json" "$out" ;; *) exit 21 ;; esac
    echo '{"ETag":"test"}' ;;
*) exit 22 ;;
esac`
	path := filepath.Join(root, "aws-fixture")
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(root, "commands.log")
	t.Setenv("STY_FAKE_AWS_LOG", log)
	t.Setenv("STY_FAKE_AWS_ROOT", root)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reader := ReadOnlyObjectLockPreflight{Bucket: "audit-bucket-test", Key: "audit/revocation.json", AWSBinary: path}
	if err := RunReadOnlyWORMPreflight(ctx, reader, pub, next, now); err != nil {
		t.Fatalf("valid fixture HOLD: %v", err)
	}
	logBytes, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	commands := string(logBytes)
	if strings.Contains(commands, "put-object") || strings.Contains(commands, "delete-object") || strings.Contains(commands, "restore") || strings.Count(commands, "get-object ") != 2 {
		t.Fatalf("unexpected command path: %s", commands)
	}
}
