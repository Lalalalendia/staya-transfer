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
	if err := RunReadOnlyWORMPreflight(context.Background(), ReadOnlyObjectLockPreflight{Bucket: "bad bucket", Key: "x"}, pub, freshMemoryAnchor(t, Head{Installation: next.Installation, Vault: next.Vault, Epoch: next.Epoch, DenyDigest: next.DenyDigest}), next, next, now); !errors.Is(err, ErrAnchorHold) {
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
	// The high-water pin must be approved and stored OUTSIDE both YDB and the
	// S3 bucket (and advanced independently after each DENY event). This env
	// interface cannot itself prove that operator custody is independent.
	minEpochText := os.Getenv("STY_WORM_PINNED_MIN_EPOCH")
	minEpoch, err := strconv.ParseUint(minEpochText, 10, 64)
	if err != nil || strconv.FormatUint(minEpoch, 10) != minEpochText {
		t.Fatal("missing or noncanonical independent high-water epoch")
	}
	minDigestRaw, err := hex.DecodeString(os.Getenv("STY_WORM_PINNED_MIN_DIGEST_HEX"))
	if err != nil || len(minDigestRaw) != 32 {
		t.Fatal("missing independent pinned high-water digest")
	}
	var minDigest [32]byte
	copy(minDigest[:], minDigestRaw)
	minimum, err := checkpointFor(Head{Installation: installation, Vault: vaultID, Epoch: minEpoch, DenyDigest: minDigest})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	ydbReader, err := NewYDBDocumentDenialReader(os.Getenv("STY_WORM_YDB_ENDPOINT"), os.Getenv("STY_WORM_YDB_TABLE"),
		func(readCtx context.Context) (string, error) {
			return readYDBProbeToken(readCtx, os.Getenv("STY_WORM_YDB_IAM_TOKEN_FILE"))
		})
	if err != nil {
		t.Fatal("invalid read-only YDB configuration")
	}
	source := ReadOnlyObjectLockPreflight{Bucket: bucket, Key: key}
	if err := RunReadOnlyWORMPreflight(ctx, source, ed25519.PublicKey(pubRaw), ydbReader, cp, minimum, time.Now()); err != nil {
		t.Fatalf("READ-ONLY Object Lock preflight: HOLD: %v", err)
	}
}

func TestReadOnlyS3AWSCliCommandAllowlistOnLinux(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mock command is not available on Windows")
	}
	pub, versions, old, next, now := wormFixture(t)
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
*list-object-versions*)
    if [ "${STY_FAKE_AWS_MISSING_IS_TRUNCATED:-0}" = 1 ]; then
      echo '{"Versions":[{"Key":"audit/revocation.json","VersionId":"v1","IsLatest":true,"Size":440},{"Key":"audit/revocation.json","VersionId":"v0","IsLatest":false,"Size":440}]}'
    elif [ "${STY_FAKE_AWS_MUTATE_LISTING:-0}" = 1 ]; then
      if [ -f "$STY_FAKE_AWS_ROOT/list_seen" ]; then
        echo '{"IsTruncated":false,"Versions":[{"Key":"audit/revocation.json","VersionId":"v1","IsLatest":false,"Size":440},{"Key":"audit/revocation.json","VersionId":"v0","IsLatest":true,"Size":440}]}'
      else
        : > "$STY_FAKE_AWS_ROOT/list_seen"
        echo '{"IsTruncated":false,"Versions":[{"Key":"audit/revocation.json","VersionId":"v1","IsLatest":true,"Size":440},{"Key":"audit/revocation.json","VersionId":"v0","IsLatest":false,"Size":440}]}'
      fi
    else
      echo '{"IsTruncated":false,"Versions":[{"Key":"audit/revocation.json","VersionId":"v1","IsLatest":true,"Size":440},{"Key":"audit/revocation.json","VersionId":"v0","IsLatest":false,"Size":440}]}'
    fi ;;
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
	ydb, state := newYDBFixture(t, Head{Installation: next.Installation, Vault: next.Vault, Epoch: next.Epoch, DenyDigest: next.DenyDigest})
	if err := RunReadOnlyWORMPreflight(ctx, reader, pub, ydb, next, next, now); err != nil {
		t.Fatalf("valid fixture HOLD: %v", err)
	}
	logBytes, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	commands := string(logBytes)
	if strings.Contains(commands, "put-object") || strings.Contains(commands, "delete-object") || strings.Contains(commands, "restore") ||
		strings.Count(commands, "get-object ") != 2 || strings.Count(commands, "list-object-versions") != 2 ||
		strings.Count(commands, "--no-paginate") != 2 || strings.Count(commands, "--max-keys 129") != 2 {
		t.Fatalf("unexpected command path or incomplete listing recheck: %s", commands)
	}
	// The first S3 listing is valid, but another version becomes current
	// during per-version body reads. The second listing must catch it.
	// Without the second ListObjectVersions the stale snapshot would PASS.
	t.Setenv("STY_FAKE_AWS_MUTATE_LISTING", "1")
	if err := RunReadOnlyWORMPreflight(ctx, reader, pub, ydb, next, next, now); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("concurrent S3 history update was accepted: %v", err)
	}
	// The YDB must be read before AND after S3. If it is restored during the
	// S3 read, equality of the initial YDB and S3 is not enough.
	t.Setenv("STY_FAKE_AWS_MUTATE_LISTING", "0")
	unstable := &changingWORMYDB{first: next, second: old}
	if err := RunReadOnlyWORMPreflight(ctx, reader, pub, unstable, next, next, now); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("YDB changed after WORM snapshot but preflight succeeded: %v", err)
	}
	if unstable.calls != 2 {
		t.Fatalf("YDB fresh read missing: %d", unstable.calls)
	}
	state.mu.Lock()
	gets, puts := state.totalGet, state.totalUpdate
	state.mu.Unlock()
	if gets != 3 || puts != 0 {
		t.Fatalf("expected read-only real HTTPS YDB requests, got reads=%d writes=%d", gets, puts)
	}
	// Omitting IsTruncated cannot be treated as an explicitly complete S3
	// page. JSON zero-value false would previously accept this mock.
	t.Setenv("STY_FAKE_AWS_MISSING_IS_TRUNCATED", "1")
	if err := RunReadOnlyWORMPreflight(ctx, reader, pub, ydb, next, next, now); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("S3 list missing IsTruncated was treated as complete: %v", err)
	}
}

// An attacker may legally delete an expired newer Object Lock version. A
// separately retained exact high-water (not copied from YDB/S3) blocks old
// genesis even when its Ed25519 signature and COMPLIANCE status are genuine.
func TestWORMPinnedMinimumBlocksValidExpiredTailRollback(t *testing.T) {
	pub, versions, old, next, now := wormFixture(t)
	genesis := versions[1]
	genesis.Latest = true
	if err := ObserveYDBAgainstWORM([]LockedWORMVersion{genesis}, pub, old, now, 7*24*time.Hour); err != nil {
		t.Fatalf("falsifier did not reproduce old unpinned acceptance: %v", err)
	}
	if err := ObserveYDBAgainstWORMWithPin([]LockedWORMVersion{genesis}, pub, old, next, now, 7*24*time.Hour); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("deleted newer epoch bypassed independent high-water: %v", err)
	}
	if err := ObserveYDBAgainstWORMWithPin(versions, pub, next, next, now, 7*24*time.Hour); err != nil {
		t.Fatalf("genuine pinned highest checkpoint refused: %v", err)
	}
	// A pinned digest must match the *specific signed record at that epoch*.
	wrong := next
	wrong.DenyDigest[0] ^= 1
	if err := ObserveYDBAgainstWORMWithPin(versions, pub, next, wrong, now, 7*24*time.Hour); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("noncanonical external pin admitted")
	}
	if err := ObserveYDBAgainstWORMWithPin(versions, pub, old, next, now, 7*24*time.Hour); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("YDB behind high-water accepted")
	}
}

// This test reader deliberately reports two different verified checkpoints
// on successive calls. No read-only S3 preflight may treat the first as final.
type changingWORMYDB struct {
	calls  int
	first  DenialCheckpoint
	second DenialCheckpoint
}

func (r *changingWORMYDB) Read(ctx context.Context, inst, vault [16]byte) (DenialCheckpoint, error) {
	if ctx == nil || ctx.Err() != nil || inst != r.first.Installation || vault != r.first.Vault {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	r.calls++
	if r.calls == 1 {
		return r.first, nil
	}
	return r.second, nil
}

// The wire format of an owner-signed WORM record must have one unambiguous
// canonical representation. The signature is over semantic checkpoint bytes;
// a second parser could otherwise interpret reordered/duplicated JSON keys
// differently without invalidating the Ed25519 signature.
func TestWORMRejectsNoncanonicalAndDuplicateJSONFields(t *testing.T) {
	pub, versions, _, next, now := wormFixture(t)
	original := string(versions[0].Payload)
	var record wormSignedRecord
	if err := json.Unmarshal(versions[0].Payload, &record); err != nil {
		t.Fatal(err)
	}
	// json.Marshal(map) sorts map keys, unlike the canonical struct order.
	alternative, err := json.Marshal(map[string]string{
		"schema": record.Schema, "installation": record.Installation, "vault": record.Vault,
		"epoch": record.Epoch, "deny_digest": record.DenyDigest,
		"commitment": record.Commitment, "previous": record.Previous,
		"signature": record.Signature,
	})
	if err != nil || string(alternative) == original {
		t.Fatal("test did not construct an alternate semantic-equivalent JSON")
	}
	duplicated := strings.Replace(original,
		`"schema":"akula-deny-worm-v1"`,
		`"schema":"akula-deny-worm-v1","schema":"akula-deny-worm-v1"`, 1)
	if duplicated == original {
		t.Fatal("test did not construct duplicate key")
	}
	for name, payload := range map[string]string{
		"prefix-whitespace": " " + original,
		"trailing-newline":  original + "\n",
		"duplicate-schema":  duplicated,
		"reordered-fields":  string(alternative),
	} {
		t.Run(name, func(t *testing.T) {
			changed := append([]LockedWORMVersion(nil), versions...)
			changed[0].Payload = []byte(payload)
			if err := ObserveYDBAgainstWORMWithPin(changed, pub, next, next, now, 7*24*time.Hour); !errors.Is(err, ErrAnchorHold) {
				t.Fatalf("noncanonical signed JSON record was accepted: %v", err)
			}
		})
	}
}
