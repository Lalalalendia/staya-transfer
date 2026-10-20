package ownerwitness

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A real HTTPS server mimics the YDB Document API wire format; it is not a
// YDB server, IAM identity, independent administrator or rollback-proof DB.
type documentAPIFixture struct {
	mu                    sync.Mutex
	row                   map[string]ydbAttr
	noResponseAfterCommit bool
	committed             chan struct{}
	forceStatus           int
	totalGet, totalUpdate int
	wireErr               error
}

func rowFor(c DenialCheckpoint) map[string]ydbAttr {
	return map[string]ydbAttr{
		"Installation":  ydbS(hex.EncodeToString(c.Installation[:])),
		"Vault":         ydbS(hex.EncodeToString(c.Vault[:])),
		"Epoch":         ydbN(strconv.FormatUint(c.Epoch, 10)),
		"DenyDigest":    ydbS(hex.EncodeToString(c.DenyDigest[:])),
		"Commitment":    ydbS(hex.EncodeToString(c.Commitment[:])),
		"SchemaVersion": ydbN(ydbSchemaVersion),
	}
}

func (f *documentAPIFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer test-token" ||
		r.Header.Get("Content-Type") != "application/json" ||
		r.Header.Get("Cache-Control") != "no-store" {
		f.mu.Lock()
		f.wireErr = errors.New("missing method/auth headers")
		f.mu.Unlock()
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		TableName                 string             `json:"TableName"`
		Key                       map[string]ydbAttr `json:"Key"`
		ConsistentRead            *bool              `json:"ConsistentRead"`
		ConditionExpression       string             `json:"ConditionExpression"`
		UpdateExpression          string             `json:"UpdateExpression"`
		ReturnValues              string             `json:"ReturnValues"`
		ExpressionAttributeNames  map[string]string  `json:"ExpressionAttributeNames"`
		ExpressionAttributeValues map[string]ydbAttr `json:"ExpressionAttributeValues"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.TableName != "test/epoch" ||
		req.Key["Installation"].S == nil || req.Key["Vault"].S == nil {
		f.mu.Lock()
		f.wireErr = errors.New("malformed table/key")
		f.mu.Unlock()
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forceStatus != 0 {
		w.WriteHeader(f.forceStatus)
		return
	}
	switch r.Header.Get("X-Amz-Target") {
	case "DynamoDB_20120810.GetItem":
		f.totalGet++
		if req.ConsistentRead == nil || !*req.ConsistentRead || req.ConditionExpression != "" || req.UpdateExpression != "" {
			f.wireErr = errors.New("eventually consistent read or unexpected field")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if f.row == nil {
			_ = json.NewEncoder(w).Encode(map[string]any{})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Item": f.row})
	case "DynamoDB_20120810.UpdateItem":
		f.totalUpdate++
		if req.ConsistentRead != nil || req.ReturnValues != "ALL_NEW" ||
			req.ConditionExpression != "attribute_exists(#pk) AND attribute_exists(#sk) AND #schema = :v1 AND #epoch = :oldE AND #digest = :oldD AND #commit = :oldC" ||
			req.UpdateExpression != "SET #epoch = :nextE, #digest = :nextD, #commit = :nextC" ||
			!reflect.DeepEqual(req.ExpressionAttributeNames, map[string]string{
				"#pk": "Installation", "#sk": "Vault", "#schema": "SchemaVersion", "#epoch": "Epoch", "#digest": "DenyDigest", "#commit": "Commitment"}) {
			f.wireErr = errors.New("mutation is not fully fenced by CAS")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		v := req.ExpressionAttributeValues
		if len(v) != 7 || f.row == nil || v[":v1"].N == nil || *v[":v1"].N != "1" ||
			f.row["Epoch"].N == nil || v[":oldE"].N == nil || *f.row["Epoch"].N != *v[":oldE"].N ||
			v[":oldD"].S == nil || *f.row["DenyDigest"].S != *v[":oldD"].S ||
			v[":oldC"].S == nil || *f.row["Commitment"].S != *v[":oldC"].S ||
			f.row["Installation"].S == nil || *f.row["Installation"].S != *req.Key["Installation"].S ||
			f.row["Vault"].S == nil || *f.row["Vault"].S != *req.Key["Vault"].S ||
			v[":nextE"].N == nil || v[":nextD"].S == nil || v[":nextC"].S == nil {
			w.WriteHeader(http.StatusBadRequest)
			return // conditional failure
		}
		f.row["Epoch"] = v[":nextE"]
		f.row["DenyDigest"] = v[":nextD"]
		f.row["Commitment"] = v[":nextC"]
		if f.noResponseAfterCommit {
			if f.committed != nil {
				close(f.committed)
				f.committed = nil
			}
			<-r.Context().Done() // simulate remote commit + lost acknowledgement
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Attributes": f.row})
	default:
		f.wireErr = errors.New("unexpected target / permission escalation")
		w.WriteHeader(http.StatusBadRequest)
	}
}

func newYDBFixture(t *testing.T, head Head) (*YDBDocumentDenialAnchor, *documentAPIFixture) {
	t.Helper()
	initial, err := checkpointFor(head)
	if err != nil {
		t.Fatal(err)
	}
	serverState := &documentAPIFixture{row: rowFor(initial)}
	srv := httptest.NewTLSServer(serverState)
	t.Cleanup(srv.Close)
	provider, err := NewYDBDocumentDenialAnchor("https://docapi.serverless.yandexcloud.net/ru-central1/folder/database", "test/epoch", func(context.Context) (string, error) { return "test-token", nil })
	if err != nil {
		t.Fatal(err)
	}
	// Inject only into the internal test instance. The public constructor can
	// never connect to a non-YDB host or disable production TLS validation.
	provider.endpoint = srv.URL
	originalRedirectPolicy := provider.client.CheckRedirect
	provider.client = srv.Client()
	provider.client.CheckRedirect = originalRedirectPolicy
	provider.client.Timeout = 5 * time.Second
	provider.client.Transport.(*http.Transport).TLSClientConfig.MinVersion = tls.VersionTLS12
	return provider, serverState
}

func TestYDBDocumentAPIDenyCASAndStrongReadOnRealHTTPS(t *testing.T) {
	path := preinstallLedger(t)
	old, err := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	if err != nil {
		t.Fatal(err)
	}
	provider, f := newYDBFixture(t, old)
	ctx := context.Background()
	found, err := provider.Read(ctx, old.Installation, old.Vault)
	expected, _ := checkpointFor(old)
	if err != nil || found != expected {
		t.Fatalf("fresh read: %v %+v", err, found)
	}
	next, err := AppendOwnerDenyWithAnchor(ctx, path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0, provider)
	if err != nil || next.Epoch != 1 {
		t.Fatalf("anchored DENY CAS: %v %+v", err, next)
	}
	post, err := ReadAnchoredDenialHead(ctx, path, testLedgerInstallation, testLedgerVault, provider)
	if err != nil || post != next {
		t.Fatalf("checkpoint mismatch: %v %+v", err, post)
	}
	f.mu.Lock()
	wireErr, nGet, nUpdate := f.wireErr, f.totalGet, f.totalUpdate
	f.mu.Unlock()
	if wireErr != nil || nGet < 3 || nUpdate != 1 {
		t.Fatalf("YDB wire mismatch: %v get=%d update=%d", wireErr, nGet, nUpdate)
	}
	newer, _ := checkpointFor(next)
	if err := provider.CompareAndSeal(ctx, expected, newer); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("stale CAS passed: %v", err)
	}
	// A remote DB row cannot be provisioned by UpdateItem: exists is mandatory.
	f.mu.Lock()
	f.row = nil
	f.mu.Unlock()
	if err := provider.CompareAndSeal(ctx, expected, newer); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("missing row inserted: %v", err)
	}
	if _, err := provider.Read(ctx, old.Installation, old.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("missing row admitted: %v", err)
	}
}

func TestYDBDeniesMalformedAbsentAndForeignCheckpoint(t *testing.T) {
	original := fixtureHead(t)
	p, f := newYDBFixture(t, original)
	ck, _ := checkpointFor(original)
	variants := []func(map[string]ydbAttr){
		func(m map[string]ydbAttr) { delete(m, "Commitment") },
		func(m map[string]ydbAttr) { m["Epoch"] = ydbN("01") },
		func(m map[string]ydbAttr) { m["Epoch"] = ydbS("1") },
		func(m map[string]ydbAttr) { m["SchemaVersion"] = ydbN("2") },
		func(m map[string]ydbAttr) {
			m["DenyDigest"] = ydbS(strings.ToUpper(hex.EncodeToString(ck.DenyDigest[:])))
		},
		func(m map[string]ydbAttr) { m["Commitment"] = ydbS(strings.Repeat("0", 64)) },
		func(m map[string]ydbAttr) { m["ForeignField"] = ydbS("should not accept") },
	}
	for i, change := range variants {
		m := rowFor(ck)
		change(m)
		f.mu.Lock()
		f.row = m
		f.mu.Unlock()
		if _, err := p.Read(context.Background(), original.Installation, original.Vault); !errors.Is(err, ErrAnchorHold) {
			t.Fatalf("invalid item %d accepted: %v", i, err)
		}
	}
	f.mu.Lock()
	f.row = rowFor(ck)
	f.forceStatus = http.StatusInternalServerError
	f.mu.Unlock()
	if _, err := p.Read(context.Background(), original.Installation, original.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("server error returned read: %v", err)
	}
	f.mu.Lock()
	f.forceStatus = 0
	f.mu.Unlock()
	if _, err := p.Read(context.Background(), [16]byte{88}, original.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("foreign namespace accepted: %v", err)
	}
}

func TestYDBLostCASAcknowledgementNeverReturnsSuccess(t *testing.T) {
	path := preinstallLedger(t)
	original, _ := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	p, f := newYDBFixture(t, original)
	committed := make(chan struct{})
	f.mu.Lock()
	f.noResponseAfterCommit = true
	f.committed = committed
	f.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	outcome := make(chan error, 1)
	go func() {
		_, err := AppendOwnerDenyWithAnchor(ctx, path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0, p)
		outcome <- err
	}()
	// Wait for real remote state mutation before cancelling the response.
	// A short fixed timeout before commit can fail on busy Windows runners.
	select {
	case <-committed:
		cancel()
	case <-time.After(5 * time.Second):
		cancel()
		<-outcome
		t.Fatal("remote conditional update never committed")
	}
	if err := <-outcome; !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("lost CAS acknowledgement should HOLD: %v", err)
	}
	// Only an independent, fresh diagnostic (after this unknown result) can
	// observe consistency. It MUST NOT be an implicit grant or auto retry.
	f.mu.Lock()
	f.noResponseAfterCommit = false
	f.mu.Unlock()
	got, err := ReadAnchoredDenialHead(context.Background(), path, testLedgerInstallation, testLedgerVault, p)
	if err != nil || got.Epoch != 1 {
		t.Fatalf("post-ambiguity read did not observe durable CAS: %v %+v", err, got)
	}
}

func TestYDBStillCannotDefeatPrivilegedRemoteRollback(t *testing.T) {
	path := preinstallLedger(t)
	oldBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	initial, _ := ReadLedgerHead(path, testLedgerInstallation, testLedgerVault)
	p, f := newYDBFixture(t, initial)
	_, err = AppendOwnerDenyWithAnchor(context.Background(), path, testLedgerInstallation, testLedgerVault, testLedgerReplica, 0, 0, p)
	if err != nil {
		t.Fatal(err)
	}
	// Privileged actor restores BOTH the local ledger and the remote DB item.
	// A strongly consistent read, a valid commitment and a CAS cannot detect it.
	if err := os.WriteFile(path, oldBytes, 0600); err != nil {
		t.Fatal(err)
	}
	old, _ := checkpointFor(initial)
	f.mu.Lock()
	f.row = rowFor(old)
	f.mu.Unlock()
	equal, err := ReadAnchoredDenialHead(context.Background(), path, testLedgerInstallation, testLedgerVault, p)
	if err != nil || equal != initial {
		t.Fatalf("rollback counterexample invalid: %v %+v", err, equal)
	}
}

// Two genuinely simultaneous HTTP clients present the same old checkpoint.
// The emulator serializes updates exactly as YDB's documented conditional
// UpdateItem. A real YDB instance is a separate, mandatory integration test.
func TestYDBConditionalUpdateHasExactlyOneWinner(t *testing.T) {
	first := fixtureHead(t)
	before, err := checkpointFor(first)
	if err != nil {
		t.Fatal(err)
	}
	floors, err := CanonicalDenyDigest([]Floor{{Replica: testLedgerReplica, Epoch: 1}})
	if err != nil {
		t.Fatal(err)
	}
	after, err := checkpointFor(Head{Installation: before.Installation, Vault: before.Vault,
		Epoch: before.Epoch + 1, DenyDigest: floors})
	if err != nil {
		t.Fatal(err)
	}
	p, f := newYDBFixture(t, first)
	barrier := make(chan struct{})
	outcome := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { <-barrier; outcome <- p.CompareAndSeal(context.Background(), before, after) }()
	}
	close(barrier)
	a, b := <-outcome, <-outcome
	if !((a == nil && errors.Is(b, ErrAnchorHold)) || (b == nil && errors.Is(a, ErrAnchorHold))) {
		t.Fatalf("exactly one update must win: a=%v b=%v", a, b)
	}
	state, err := p.Read(context.Background(), before.Installation, before.Vault)
	if err != nil || state != after {
		t.Fatalf("remote CAS left inconsistent state: %v %+v", err, state)
	}
	f.mu.Lock()
	updates := f.totalUpdate
	f.mu.Unlock()
	if updates != 2 {
		t.Fatalf("CAS must use two independent HTTP calls, got %d", updates)
	}
}

func TestYDBConfigurationAndCredentialsAreFailClosed(t *testing.T) {
	token := func(context.Context) (string, error) { return "test-token", nil }
	invalid := []string{"http://docapi.serverless.yandexcloud.net/path", "https://evil.example/path", "https://user:password@docapi.serverless.yandexcloud.net/ru-central1/a/b", "https://docapi.serverless.yandexcloud.net/ru-central1/a/b?secret=1", "https://docapi.serverless.yandexcloud.net/ru-central1/a/../b", "https://docapi.serverless.yandexcloud.net/ru-central1/a/b/"}
	for _, s := range invalid {
		if _, err := NewYDBDocumentDenialAnchor(s, "test/epoch", token); !errors.Is(err, ErrAnchorHold) {
			t.Fatalf("accepted URL %s", s)
		}
	}
	if _, err := NewYDBDocumentDenialAnchor("https://docapi.serverless.yandexcloud.net/ru-central1/folder/db", "test/epoch", nil); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("accepted nil token source")
	}
	p, f := newYDBFixture(t, fixtureHead(t))
	p.token = func(context.Context) (string, error) { return "\r\nsteal: yes", nil }
	_, err := p.Read(context.Background(), testLedgerInstallation, testLedgerVault)
	if !errors.Is(err, ErrAnchorHold) {
		t.Fatalf("credential injection accepted: %v", err)
	}
	f.mu.Lock()
	count := f.totalGet
	f.mu.Unlock()
	if count != 0 {
		t.Fatal("invalid token still sent HTTP request")
	}
}

// Regression: the reader's public method set cannot satisfy a sealing port.
// The same HTTPS fixture proves that reader preflight causes GetItem only.
func TestYDBReaderIsReadOnlyCapability(t *testing.T) {
	h := fixtureHead(t)
	full, state := newYDBFixture(t, h)
	reader := &YDBDocumentDenialReader{client: full}
	if _, ok := any(reader).(TrustedDenialAnchor); ok {
		t.Fatal("read-only YDB adapter unexpectedly exposes CAS")
	}
	expected, err := checkpointFor(h)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.Read(context.Background(), h.Installation, h.Vault)
	if err != nil || got != expected {
		t.Fatalf("read-only preflight HOLD: %v", err)
	}
	state.mu.Lock()
	reads, writes := state.totalGet, state.totalUpdate
	state.mu.Unlock()
	if reads != 1 || writes != 0 {
		t.Fatalf("preflight mutated record: gets=%d updates=%d", reads, writes)
	}
	if _, err := (*YDBDocumentDenialReader)(nil).Read(context.Background(), h.Installation, h.Vault); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("nil reader did not fail closed")
	}
	if _, err := NewYDBDocumentDenialReader("https://evil.example/db", "test/epoch", func(context.Context) (string, error) { return "test-token", nil }); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("untrusted reader endpoint accepted")
	}
}

// readYDBProbeToken keeps IAM credentials out of command-line arguments and
// logs. It rejects symlinks, nonregular files and accessible Unix secrets.
// Operators must separately protect all parent directories and on Windows
// must verify native ACLs: os.FileMode does not describe Windows DACLs.
func readYDBProbeToken(ctx context.Context, path string) (string, error) {
	if ctx == nil || ctx.Err() != nil || path == "" {
		return "", ErrAnchorHold
	}
	prior, err := os.Lstat(path)
	if err != nil || !prior.Mode().IsRegular() || prior.Size() < 1 || prior.Size() > 16384 {
		return "", ErrAnchorHold
	}
	if runtime.GOOS != "windows" && prior.Mode().Perm()&0077 != 0 {
		return "", ErrAnchorHold
	}
	f, err := os.Open(path)
	if err != nil {
		return "", ErrAnchorHold
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(prior, opened) {
		return "", ErrAnchorHold
	}
	buf, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(buf) < 1 || len(buf) > 16384 || ctx.Err() != nil {
		return "", ErrAnchorHold
	}
	token := strings.TrimSuffix(string(buf), "\n")
	if token == "" || token != strings.TrimSpace(token) {
		return "", ErrAnchorHold
	}
	for i := 0; i < len(token); i++ {
		if token[i] <= 32 || token[i] >= 127 {
			return "", ErrAnchorHold
		}
	}
	return token, nil
}

func TestYDBProbeTokenFileRejectsUnsafeInputs(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "iam-token")
	if err := os.WriteFile(good, []byte("dummy-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readYDBProbeToken(context.Background(), good)
	if err != nil || got != "dummy-token" {
		t.Fatalf("valid local token file unavailable: %v", err)
	}
	if _, err = readYDBProbeToken(context.Background(), filepath.Join(dir, "missing")); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("missing token file accepted")
	}
	if _, err = readYDBProbeToken(context.Background(), dir); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("directory token accepted")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(good, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err = readYDBProbeToken(context.Background(), good); !errors.Is(err, ErrAnchorHold) {
			t.Fatal("group-readable credential accepted")
		}
		if err := os.Chmod(good, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "token-link")
		if err := os.Symlink(good, link); err == nil {
			if _, err := readYDBProbeToken(context.Background(), link); !errors.Is(err, ErrAnchorHold) {
				t.Fatal("symlink credential accepted")
			}
		}
	}
	if err := os.WriteFile(good, []byte("dummy\r\ninjection"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readYDBProbeToken(context.Background(), good); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("header injection token accepted")
	}
	if err := os.WriteFile(good, []byte(strings.Repeat("z", 16385)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readYDBProbeToken(context.Background(), good); !errors.Is(err, ErrAnchorHold) {
		t.Fatal("oversized token accepted")
	}
}

// This is an explicitly opt-in REAL YDB READ, NOT a CI proof. No writes,
// no auto-provisioning and no cached fallback. No secrets or remote data logged.
// All STY_YDB_LIVE_* inputs are required when STY_YDB_LIVE_READ=1.
func TestYDBLiveReadOnlyPreflight(t *testing.T) {
	if os.Getenv("STY_YDB_LIVE_READ") != "1" {
		t.Skip("NOT RUN: requires separately provisioned real YDB database and viewer IAM principal")
	}
	required := []string{"STY_YDB_LIVE_ENDPOINT", "STY_YDB_LIVE_TABLE", "STY_YDB_LIVE_INSTALLATION", "STY_YDB_LIVE_VAULT", "STY_YDB_LIVE_EPOCH", "STY_YDB_LIVE_DENY_DIGEST", "STY_YDB_LIVE_IAM_TOKEN_FILE"}
	for _, name := range required {
		if os.Getenv(name) == "" {
			t.Fatalf("HOLD: missing required field %s", name)
		}
	}
	parse16 := func(key string) [16]byte {
		var v [16]byte
		decoded, ok := canonicalHex(os.Getenv(key), 16)
		if !ok {
			t.Fatalf("HOLD: malformed %s", key)
		}
		copy(v[:], decoded)
		if v == [16]byte{} {
			t.Fatalf("HOLD: zero %s", key)
		}
		return v
	}
	inst, vault := parse16("STY_YDB_LIVE_INSTALLATION"), parse16("STY_YDB_LIVE_VAULT")
	epoch, err := strconv.ParseUint(os.Getenv("STY_YDB_LIVE_EPOCH"), 10, 64)
	if err != nil || strconv.FormatUint(epoch, 10) != os.Getenv("STY_YDB_LIVE_EPOCH") {
		t.Fatal("HOLD: invalid canonical epoch")
	}
	digest, ok := canonicalHex(os.Getenv("STY_YDB_LIVE_DENY_DIGEST"), 32)
	if !ok {
		t.Fatal("HOLD: invalid canonical DENY digest")
	}
	var h Head
	h.Installation, h.Vault, h.Epoch = inst, vault, epoch
	copy(h.DenyDigest[:], digest)
	expected, err := checkpointFor(h)
	if err != nil {
		t.Fatal("HOLD: invalid expected checkpoint")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	source := func(requestCtx context.Context) (string, error) {
		return readYDBProbeToken(requestCtx, os.Getenv("STY_YDB_LIVE_IAM_TOKEN_FILE"))
	}
	reader, err := NewYDBDocumentDenialReader(os.Getenv("STY_YDB_LIVE_ENDPOINT"), os.Getenv("STY_YDB_LIVE_TABLE"), source)
	if err != nil {
		t.Fatal("HOLD: invalid YDB live reader configuration")
	}
	got, err := reader.Read(ctx, inst, vault)
	if err != nil || got != expected {
		t.Fatal("HOLD: live strongly-consistent YDB checkpoint absent or divergent")
	}
	t.Log("LIVE YDB READ-ONLY PREFLIGHT: DENY checkpoint matches; no authorization or CAS granted")
}
