package ownerwitness

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
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
	provider.client = srv.Client()
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