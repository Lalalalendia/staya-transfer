package ownerwitness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RN-4E1b-03c1c1: read-only verification of independently retained S3
// object versions. This is a RESEARCH PREFLIGHT, not an online grant gate.
// Object Lock protects individual versions; it does not lock a key or prove
// that the operator, listing service, signing key, and backup admin are separate.
const wormDomain = "AKULA_DENY_WORM_VERSION_V1\x00"
const wormSchema = "akula-deny-worm-v1"
const wormMaxVersions = 128
const wormMaxObjectBytes = 4096

var s3BucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{2,62}$`)
var s3KeyName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./-]{0,191}$`)

type LockedWORMVersion struct {
	ID          string
	Latest      bool
	Mode        string
	RetainUntil time.Time
	Payload     []byte
}

type wormSignedRecord struct {
	Schema       string `json:"schema"`
	Installation string `json:"installation"`
	Vault        string `json:"vault"`
	Epoch        string `json:"epoch"`
	DenyDigest   string `json:"deny_digest"`
	Commitment   string `json:"commitment"`
	Previous     string `json:"previous"`
	Signature    string `json:"signature"`
}

type verifiedWORMRecord struct {
	checkpoint DenialCheckpoint
	previous   [32]byte
	recordHash [32]byte
	versionID  string
	latest     bool
}

func strictWORMHex(s string, count int) ([]byte, bool) {
	if len(s) != count*2 || strings.ToLower(s) != s {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	return b, err == nil && hex.EncodeToString(b) == s
}

// A canonical signature covers the actual checkpoint identity, global epoch,
// complete DENY-floor digest, cryptographic commitment, and PREVIOUS record
// hash. It never signs arbitrary JSON serialization or a mutable S3 key name.
func wormSignaturePayload(c DenialCheckpoint, previous [32]byte) []byte {
	payload := make([]byte, 0, len(wormDomain)+16+16+8+32+32+32)
	payload = append(payload, wormDomain...)
	payload = append(payload, c.Installation[:]...)
	payload = append(payload, c.Vault[:]...)
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], c.Epoch)
	payload = append(payload, n[:]...)
	payload = append(payload, c.DenyDigest[:]...)
	payload = append(payload, c.Commitment[:]...)
	payload = append(payload, previous[:]...)
	return payload
}

func inspectWORMVersion(v LockedWORMVersion, owner ed25519.PublicKey, inst, vault [16]byte, now time.Time, minimumRemaining time.Duration) (verifiedWORMRecord, error) {
	var zero verifiedWORMRecord
	if len(owner) != ed25519.PublicKeySize || inst == [16]byte{} || vault == [16]byte{} ||
		v.ID == "" || v.ID == "null" || len(v.ID) > 512 || len(v.Payload) == 0 ||
		len(v.Payload) > wormMaxObjectBytes || v.Mode != "COMPLIANCE" ||
		!v.RetainUntil.After(now.Add(minimumRemaining)) {
		return zero, ErrAnchorHold
	}
	var rec wormSignedRecord
	dec := json.NewDecoder(bytes.NewReader(v.Payload))
	dec.DisallowUnknownFields()
	if dec.Decode(&rec) != nil {
		return zero, ErrAnchorHold
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || rec.Schema != wormSchema {
		return zero, ErrAnchorHold
	}
	// Disallow duplicate keys, alternative field ordering, insignificant
	// whitespace and escaped spellings. Ed25519 signs semantic checkpoint
	// bytes, so a second JSON implementation must not see a different record.
	// Go's wormSignedRecord field order is the protocol's canonical wire form.
	canonical, err := json.Marshal(rec)
	if err != nil || !bytes.Equal(canonical, v.Payload) {
		return zero, ErrAnchorHold
	}
	installation, okI := strictWORMHex(rec.Installation, 16)
	vlt, okV := strictWORMHex(rec.Vault, 16)
	digest, okD := strictWORMHex(rec.DenyDigest, 32)
	commitment, okC := strictWORMHex(rec.Commitment, 32)
	previous, okP := strictWORMHex(rec.Previous, 32)
	if !okI || !okV || !okD || !okC || !okP ||
		!bytes.Equal(installation, inst[:]) || !bytes.Equal(vlt, vault[:]) {
		return zero, ErrAnchorHold
	}
	epoch, err := strconv.ParseUint(rec.Epoch, 10, 64)
	if err != nil || strconv.FormatUint(epoch, 10) != rec.Epoch {
		return zero, ErrAnchorHold
	}
	var dig [32]byte
	copy(dig[:], digest)
	c, err := checkpointFor(Head{Installation: inst, Vault: vault, Epoch: epoch, DenyDigest: dig})
	if err != nil || !bytes.Equal(commitment, c.Commitment[:]) {
		return zero, ErrAnchorHold
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(rec.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(sig) != rec.Signature {
		return zero, ErrAnchorHold
	}
	var prev [32]byte
	copy(prev[:], previous)
	message := wormSignaturePayload(c, prev)
	if !ed25519.Verify(owner, message, sig) {
		return zero, ErrAnchorHold
	}
	digestHash := sha256.New()
	digestHash.Write(message)
	digestHash.Write(sig)
	var hash [32]byte
	copy(hash[:], digestHash.Sum(nil))
	return verifiedWORMRecord{checkpoint: c, previous: prev, recordHash: hash, versionID: v.ID, latest: v.Latest}, nil
}

// InspectWORMVersions requires the COMPLETE version history from genesis at
// epoch zero. A missing page, gap, delete marker, unsigned version, replayed
// version, insufficient COMPLIANCE retention, fork, or two "latest" objects
// is HOLD. Comparing a single current-key GetObject is NEVER sufficient.
// In particular, COMPLIANCE retention expires; this function is NOT an
// unconditional lifetime guarantee or independent-trust proof.
func InspectWORMVersions(versions []LockedWORMVersion, owner ed25519.PublicKey, inst, vault [16]byte, now time.Time, minimumRemaining time.Duration) (DenialCheckpoint, error) {
	if len(versions) == 0 || len(versions) > wormMaxVersions || len(owner) != ed25519.PublicKeySize ||
		minimumRemaining < 24*time.Hour || minimumRemaining > 365*24*time.Hour || now.IsZero() {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	rows := make([]verifiedWORMRecord, 0, len(versions))
	ids := make(map[string]struct{}, len(versions))
	for _, version := range versions {
		if _, duplicate := ids[version.ID]; duplicate {
			return DenialCheckpoint{}, ErrAnchorHold
		}
		ids[version.ID] = struct{}{}
		inspected, err := inspectWORMVersion(version, owner, inst, vault, now, minimumRemaining)
		if err != nil {
			return DenialCheckpoint{}, ErrAnchorHold
		}
		rows = append(rows, inspected)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].checkpoint.Epoch < rows[j].checkpoint.Epoch })
	var prevHash [32]byte
	latestCount := 0
	for i, row := range rows {
		if row.checkpoint.Epoch != uint64(i) || row.previous != prevHash {
			return DenialCheckpoint{}, ErrAnchorHold
		}
		if row.latest {
			latestCount++
			if i != len(rows)-1 {
				return DenialCheckpoint{}, ErrAnchorHold
			}
		}
		prevHash = row.recordHash
	}
	if latestCount != 1 {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	return rows[len(rows)-1].checkpoint, nil
}

// ObserveYDBAgainstWORM is diagnostic-only: it cannot authorize a file,
// P2P peer, write, receipt, APPLIED or ACK. It requires the independent S3
// high-water chain to match a fresh already-obtained YDB checkpoint exactly.
func ObserveYDBAgainstWORM(versions []LockedWORMVersion, owner ed25519.PublicKey, ydb DenialCheckpoint, now time.Time, minimumRemaining time.Duration) error {
	if !validCASCheckpoint(ydb) {
		return ErrAnchorHold
	}
	high, err := InspectWORMVersions(versions, owner, ydb.Installation, ydb.Vault, now, minimumRemaining)
	if err != nil || high != ydb {
		return ErrAnchorHold
	}
	return nil
}

// ReadOnlyObjectLockPreflight runs *only* AWS CLI S3 read operations against
// the fixed Yandex Object Storage endpoint. The CLI receives its own operator
// AWS_PROFILE/temporary credentials; nothing is written to GitHub or the DB.
// It checks bucket versioning, default COMPLIANCE lock, ALL exact-key
// versions, per-version retention, and exact version payloads.
// This helper does not deploy a bucket, mint credentials or prove admins differ.
// Comparing the complete listing metadata before and after per-version reads
// catches ordinary concurrent S3 mutations. It is only a best-effort TOCTOU
// check; it cannot authenticate a dishonest S3 list endpoint or prove custody.
type wormS3VersionList struct {
	Versions []struct {
		Key          string
		VersionId    string
		IsLatest     bool
		Size         int64
		ETag         string
		LastModified string
	}
	DeleteMarkers []struct {
		Key       string
		VersionId string
		IsLatest  bool
	}
	// A missing IsTruncated is UNKNOWN, never proof of completeness.
	IsTruncated         *bool
	NextKeyMarker       string
	NextVersionIdMarker string
}

type ReadOnlyObjectLockPreflight struct {
	Bucket    string
	Key       string
	AWSBinary string
}

func (p ReadOnlyObjectLockPreflight) query(ctx context.Context, max int, args ...string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrAnchorHold
	}
	bin := p.AWSBinary
	if bin == "" {
		bin = "aws"
	}
	argv := append([]string{"--endpoint-url", "https://storage.yandexcloud.net", "--no-cli-pager", "--output", "json", "s3api"}, args...)
	cmd := exec.CommandContext(ctx, bin, argv...)
	cmd.Env = append(os.Environ(), "AWS_EC2_METADATA_DISABLED=true")
	out, err := cmd.Output()
	if err != nil || len(out) == 0 || len(out) > max || ctx.Err() != nil {
		return nil, ErrAnchorHold
	}
	return out, nil
}

func (p ReadOnlyObjectLockPreflight) Read(ctx context.Context) ([]LockedWORMVersion, error) {
	if !s3BucketName.MatchString(p.Bucket) || strings.Contains(p.Bucket, "..") || !s3KeyName.MatchString(p.Key) ||
		strings.Contains(p.Key, "..") || strings.Contains(p.Key, "//") || strings.HasSuffix(p.Key, "/") {
		return nil, ErrAnchorHold
	}
	var bv struct{ Status string }
	b, err := p.query(ctx, 16*1024, "get-bucket-versioning", "--bucket", p.Bucket)
	if err != nil || json.Unmarshal(b, &bv) != nil || bv.Status != "Enabled" {
		return nil, ErrAnchorHold
	}
	var lc struct {
		ObjectLockConfiguration struct {
			ObjectLockEnabled string
			Rule              struct{ DefaultRetention struct{ Mode string } }
		}
	}
	b, err = p.query(ctx, 16*1024, "get-object-lock-configuration", "--bucket", p.Bucket)
	if err != nil || json.Unmarshal(b, &lc) != nil || lc.ObjectLockConfiguration.ObjectLockEnabled != "Enabled" ||
		lc.ObjectLockConfiguration.Rule.DefaultRetention.Mode != "COMPLIANCE" {
		return nil, ErrAnchorHold
	}
	// A single, explicitly bounded S3 API page is deliberate: never allow
	// the AWS CLI's automatic pagination to conceal a truncated snapshot.
	// The 129th version is an overflow sentinel; the accepted limit is 128.
	listVersions := func() (wormS3VersionList, error) {
		var listing wormS3VersionList
		data, err := p.query(ctx, 1024*1024, "list-object-versions", "--bucket", p.Bucket,
			"--prefix", p.Key, "--max-keys", "129", "--no-paginate")
		if err != nil || json.Unmarshal(data, &listing) != nil || listing.IsTruncated == nil || *listing.IsTruncated ||
			listing.NextKeyMarker != "" || listing.NextVersionIdMarker != "" ||
			len(listing.Versions)+len(listing.DeleteMarkers) > wormMaxVersions {
			return wormS3VersionList{}, ErrAnchorHold
		}
		return listing, nil
	}
	listing, err := listVersions()
	if err != nil {
		return nil, ErrAnchorHold
	}
	for _, marker := range listing.DeleteMarkers {
		if marker.Key == p.Key {
			return nil, ErrAnchorHold
		}
	}
	out := make([]LockedWORMVersion, 0, len(listing.Versions))
	for _, v := range listing.Versions {
		if v.Key != p.Key {
			continue
		}
		if len(out) >= wormMaxVersions || v.VersionId == "" || v.VersionId == "null" ||
			len(v.VersionId) > 512 || v.Size <= 0 || v.Size > wormMaxObjectBytes {
			return nil, ErrAnchorHold
		}
		var retention struct {
			Retention struct {
				Mode            string
				RetainUntilDate string
			}
		}
		b, err = p.query(ctx, 16*1024, "get-object-retention", "--bucket", p.Bucket, "--key", p.Key, "--version-id", v.VersionId)
		if err != nil || json.Unmarshal(b, &retention) != nil || retention.Retention.Mode != "COMPLIANCE" {
			return nil, ErrAnchorHold
		}
		until, err := time.Parse(time.RFC3339Nano, retention.Retention.RetainUntilDate)
		if err != nil {
			return nil, ErrAnchorHold
		}
		temporary, err := os.CreateTemp("", "akula-worm-read-only-*")
		if err != nil {
			return nil, ErrAnchorHold
		}
		path := temporary.Name()
		temporary.Close()
		// Untrusted output path is generated locally, never supplied by remote.
		response, err := p.query(ctx, 16*1024, "get-object", "--bucket", p.Bucket, "--key", p.Key, "--version-id", v.VersionId, path)
		content, readErr := os.ReadFile(path)
		_ = os.Remove(path)
		// `get-object` writes its body to the local outfile but returns the
		// response headers as JSON on stdout. The request's VersionId alone
		// does NOT prove that the returned body belongs to that version.
		// Bind returned version, length and opaque ETag to the first S3
		// listing and downloaded bytes, independently of Ed25519 validation.
		var object struct {
			VersionId     string
			ContentLength *int64
			ETag          string
			DeleteMarker  bool
			ContentRange  string
		}
		if err != nil || readErr != nil || json.Unmarshal(response, &object) != nil ||
			object.VersionId != v.VersionId || object.ETag == "" ||
			v.ETag == "" || object.ETag != v.ETag || object.ContentLength == nil ||
			*object.ContentLength != v.Size || int64(len(content)) != v.Size ||
			len(content) == 0 || len(content) > wormMaxObjectBytes || object.DeleteMarker || object.ContentRange != "" {
			return nil, ErrAnchorHold
		}
		out = append(out, LockedWORMVersion{ID: v.VersionId, Latest: v.IsLatest, Mode: retention.Retention.Mode, RetainUntil: until, Payload: content})
	}
	if len(out) == 0 {
		return nil, ErrAnchorHold
	}
	// A newly uploaded version, new delete marker, changed IsLatest flag or
	// altered version metadata during GetObject/GetObjectRetention must HOLD.
	// No cached or earlier successful listing may stand in for this reread.
	fresh, err := listVersions()
	if err != nil || !reflect.DeepEqual(listing, fresh) {
		return nil, ErrAnchorHold
	}
	return out, nil
}

// ObserveYDBAgainstWORMWithPin requires a separately protected high-water
// checkpoint. This pin MUST be obtained from independent custody and advanced
// after every accepted revoke. Copying it from today's YDB/S3 listing defeats
// its purpose. A Go argument alone does not establish nonrollbackable storage.
// The pinned exact commitment must occur in the signed retained chain, not
// merely a checkpoint with a numerically greater epoch.
func ObserveYDBAgainstWORMWithPin(versions []LockedWORMVersion, owner ed25519.PublicKey, ydb, pinnedMinimum DenialCheckpoint, now time.Time, minimumRemaining time.Duration) error {
	if !validCASCheckpoint(pinnedMinimum) || !validCASCheckpoint(ydb) ||
		pinnedMinimum.Installation != ydb.Installation || pinnedMinimum.Vault != ydb.Vault ||
		pinnedMinimum.Epoch > ydb.Epoch ||
		ObserveYDBAgainstWORM(versions, owner, ydb, now, minimumRemaining) != nil {
		return ErrAnchorHold
	}
	found := false
	for _, version := range versions {
		row, err := inspectWORMVersion(version, owner, ydb.Installation, ydb.Vault, now, minimumRemaining)
		if err != nil {
			return ErrAnchorHold
		}
		if row.checkpoint.Epoch == pinnedMinimum.Epoch {
			if row.checkpoint != pinnedMinimum || found {
				return ErrAnchorHold
			}
			found = true
		}
	}
	if !found {
		return ErrAnchorHold
	}
	return nil
}

// RunReadOnlyWORMPreflight reads real YDB on BOTH sides of the bounded,
// double-listed S3 history inspection, requiring exact operator-expected state
// and an independently pinned minimum. The two sources are not a transaction:
// this is fail-closed DIAGNOSTICS ONLY and cannot grant any permission.
// It takes only DenialAnchorReader, never a writer or CAS authority.
func RunReadOnlyWORMPreflight(ctx context.Context, source ReadOnlyObjectLockPreflight, owner ed25519.PublicKey,
	ydb DenialAnchorReader, expected, pinnedMinimum DenialCheckpoint, now time.Time) error {
	if ctx == nil || ctx.Err() != nil || ydb == nil || !validCASCheckpoint(expected) ||
		!validCASCheckpoint(pinnedMinimum) || len(owner) != ed25519.PublicKeySize ||
		expected.Installation != pinnedMinimum.Installation || expected.Vault != pinnedMinimum.Vault ||
		pinnedMinimum.Epoch > expected.Epoch {
		return ErrAnchorHold
	}
	before, err := ydb.Read(ctx, expected.Installation, expected.Vault)
	if err != nil || ctx.Err() != nil || before != expected {
		return ErrAnchorHold
	}
	values, err := source.Read(ctx)
	if err != nil || ctx.Err() != nil ||
		ObserveYDBAgainstWORMWithPin(values, owner, expected, pinnedMinimum, now, 7*24*time.Hour) != nil {
		return ErrAnchorHold
	}
	after, err := ydb.Read(ctx, expected.Installation, expected.Vault)
	if err != nil || ctx.Err() != nil || after != before {
		return ErrAnchorHold
	}
	return nil
}
