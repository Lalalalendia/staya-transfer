package ownerwitness

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RN-4E1b-03c1b6: a strictly DENY-only remote conditional-update adapter.
// It proves the Document API wire contract, NOT independent custody or
// rollback-resistant administration of the remote database. Neither a
// consistent read nor a conditional update prevents a privileged DB restore.
// The remote table and row MUST be provisioned by a different principal.
const (
	ydbHost          = "docapi.serverless.yandexcloud.net"
	ydbMaxResponse   = 16384
	ydbSchemaVersion = "1"
)

var ydbTablePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*$`)

// IAMTokenSource must retrieve a freshly valid IAM token from a separate,
// protected service identity. Credentials are never stored or logged here.
// Do not supply this source from an Akula desktop application.
type IAMTokenSource func(context.Context) (string, error)

// YDBDocumentDenialAnchor is a client for a separately operated YDB Document
// API instance. Its CAS is effective against concurrent writers only if DB
// roles and the underlying record cannot be rewritten/rolled back by the
// attacker. It is never a positive grant authority.
type YDBDocumentDenialAnchor struct {
	endpoint string
	table    string
	token    IAMTokenSource
	client   *http.Client
}

var _ TrustedDenialAnchor = (*YDBDocumentDenialAnchor)(nil)

// YDBDocumentDenialReader is a deliberately weaker READ-ONLY capability.
// It does not expose CompareAndSeal. Deploy it using an IAM principal with
// independently VERIFIED read-only YDB permissions (for example ydb.viewer
// scoped to the intended database). Merely using this Go type cannot restrict
// a privileged IAM token holder from issuing API requests by other means.
type YDBDocumentDenialReader struct {
	client *YDBDocumentDenialAnchor
}

var _ DenialAnchorReader = (*YDBDocumentDenialReader)(nil)

func NewYDBDocumentDenialReader(endpoint, table string, token IAMTokenSource) (*YDBDocumentDenialReader, error) {
	client, err := NewYDBDocumentDenialAnchor(endpoint, table, token)
	if err != nil {
		return nil, ErrAnchorHold
	}
	return &YDBDocumentDenialReader{client: client}, nil
}

func (r *YDBDocumentDenialReader) Read(ctx context.Context, installation, vault [16]byte) (DenialCheckpoint, error) {
	if r == nil || r.client == nil {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	return r.client.Read(ctx, installation, vault)
}

// The production factory restricts credentials to the documented YDB host.
// Only a preprovisioned document table with HASH Installation and RANGE Vault
// keys is supported. A custom HTTP transport is NOT exposed to product code.
func NewYDBDocumentDenialAnchor(endpoint, table string, token IAMTokenSource) (*YDBDocumentDenialAnchor, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host != ydbHost ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" ||
		!strings.HasPrefix(u.Path, "/ru-central1/") || strings.HasSuffix(u.Path, "/") ||
		strings.Contains(u.Path, "..") || strings.Contains(u.Path, "//") ||
		len(table) < 3 || len(table) > 255 || !ydbTablePattern.MatchString(table) ||
		strings.Contains(table, "..") || token == nil {
		return nil, ErrAnchorHold
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	// Explicitly do not use ambient HTTP_PROXY or credential-bearing redirects.
	return &YDBDocumentDenialAnchor{endpoint: endpoint, table: table, token: token,
		client: &http.Client{Timeout: 4 * time.Second, Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}}, nil
}

type ydbAttr struct {
	S *string `json:"S,omitempty"`
	N *string `json:"N,omitempty"`
}

func ydbS(s string) ydbAttr { return ydbAttr{S: &s} }
func ydbN(n string) ydbAttr { return ydbAttr{N: &n} }
func ydbKey(installation, vault [16]byte) map[string]ydbAttr {
	return map[string]ydbAttr{
		"Installation": ydbS(hex.EncodeToString(installation[:])),
		"Vault":        ydbS(hex.EncodeToString(vault[:])),
	}
}

func (d *YDBDocumentDenialAnchor) call(ctx context.Context, method string, payload any, output any) error {
	if ctx == nil || ctx.Err() != nil || d == nil || d.client == nil || d.token == nil {
		return ErrAnchorHold
	}
	tok, err := d.token(ctx)
	if err != nil || len(tok) == 0 || len(tok) > 16384 || strings.TrimSpace(tok) != tok {
		return ErrAnchorHold
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] <= 32 || tok[i] >= 127 {
			return ErrAnchorHold
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ErrAnchorHold
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, bytes.NewReader(body))
	if err != nil {
		return ErrAnchorHold
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Amz-Target", "DynamoDB_20120810."+method)
	req.Header.Set("Cache-Control", "no-store")
	res, err := d.client.Do(req)
	if err != nil || ctx.Err() != nil {
		return ErrAnchorHold
	}
	defer res.Body.Close()
	// ConditionalCheckFailedException, missing table, access denial, 429 and
	// unknown commit status all become HOLD. There is no implicit retry.
	if res.StatusCode != http.StatusOK {
		return ErrAnchorHold
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, ydbMaxResponse+1))
	if err != nil || len(data) == 0 || len(data) > ydbMaxResponse {
		return ErrAnchorHold
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil {
		return ErrAnchorHold
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || ctx.Err() != nil {
		return ErrAnchorHold
	}
	return nil
}

func ydbString(item map[string]ydbAttr, key string) (string, bool) {
	v, exists := item[key]
	return value(v.S), exists && v.S != nil && v.N == nil
}
func ydbNumber(item map[string]ydbAttr, key string) (string, bool) {
	v, exists := item[key]
	return value(v.N), exists && v.N != nil && v.S == nil
}
func value(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
func canonicalHex(s string, byteLen int) ([]byte, bool) {
	if len(s) != byteLen*2 {
		return nil, false
	}
	v, err := hex.DecodeString(s)
	return v, err == nil && hex.EncodeToString(v) == s
}
func parseYDBItem(item map[string]ydbAttr, inst, vault [16]byte) (DenialCheckpoint, error) {
	if len(item) != 6 {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	is, iok := ydbString(item, "Installation")
	vs, vok := ydbString(item, "Vault")
	e, eok := ydbNumber(item, "Epoch")
	ds, dok := ydbString(item, "DenyDigest")
	cs, cok := ydbString(item, "Commitment")
	version, sok := ydbNumber(item, "SchemaVersion")
	if !iok || !vok || !eok || !dok || !cok || !sok || version != ydbSchemaVersion ||
		is != hex.EncodeToString(inst[:]) || vs != hex.EncodeToString(vault[:]) {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	num, err := strconv.ParseUint(e, 10, 64)
	if err != nil || strconv.FormatUint(num, 10) != e {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	deny, ok := canonicalHex(ds, 32)
	if !ok {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	commitment, ok := canonicalHex(cs, 32)
	if !ok {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	var h Head
	h.Installation = inst
	h.Vault = vault
	h.Epoch = num
	copy(h.DenyDigest[:], deny)
	ck, err := checkpointFor(h)
	if err != nil || !bytes.Equal(ck.Commitment[:], commitment) {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	return ck, nil
}

func (d *YDBDocumentDenialAnchor) Read(ctx context.Context, installation, vault [16]byte) (DenialCheckpoint, error) {
	if d == nil || installation == [16]byte{} || vault == [16]byte{} || ctx == nil || ctx.Err() != nil {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	var result struct {
		Item map[string]ydbAttr `json:"Item"`
	}
	err := d.call(ctx, "GetItem", struct {
		TableName      string             `json:"TableName"`
		Key            map[string]ydbAttr `json:"Key"`
		ConsistentRead bool               `json:"ConsistentRead"`
	}{d.table, ydbKey(installation, vault), true}, &result)
	if err != nil {
		return DenialCheckpoint{}, ErrAnchorHold
	}
	return parseYDBItem(result.Item, installation, vault)
}

func (d *YDBDocumentDenialAnchor) CompareAndSeal(ctx context.Context, old, next DenialCheckpoint) error {
	if d == nil || ctx == nil || ctx.Err() != nil || old.Installation == [16]byte{} || old.Vault == [16]byte{} ||
		old.Installation != next.Installation || old.Vault != next.Vault || old.Epoch == math.MaxUint64 ||
		next.Epoch != old.Epoch+1 || next.DenyDigest == old.DenyDigest {
		return ErrAnchorHold
	}
	for _, v := range []DenialCheckpoint{old, next} {
		h := Head{Installation: v.Installation, Vault: v.Vault, Epoch: v.Epoch, DenyDigest: v.DenyDigest}
		expected, err := checkpointFor(h)
		if err != nil || v != expected {
			return ErrAnchorHold
		}
	}
	var result struct {
		Attributes map[string]ydbAttr `json:"Attributes"`
	}
	err := d.call(ctx, "UpdateItem", struct {
		TableName                 string             `json:"TableName"`
		Key                       map[string]ydbAttr `json:"Key"`
		ConditionExpression       string             `json:"ConditionExpression"`
		UpdateExpression          string             `json:"UpdateExpression"`
		ExpressionAttributeNames  map[string]string  `json:"ExpressionAttributeNames"`
		ExpressionAttributeValues map[string]ydbAttr `json:"ExpressionAttributeValues"`
		ReturnValues              string             `json:"ReturnValues"`
	}{
		TableName: d.table, Key: ydbKey(old.Installation, old.Vault),
		ConditionExpression:      "attribute_exists(#pk) AND attribute_exists(#sk) AND #schema = :v1 AND #epoch = :oldE AND #digest = :oldD AND #commit = :oldC",
		UpdateExpression:         "SET #epoch = :nextE, #digest = :nextD, #commit = :nextC",
		ExpressionAttributeNames: map[string]string{"#pk": "Installation", "#sk": "Vault", "#schema": "SchemaVersion", "#epoch": "Epoch", "#digest": "DenyDigest", "#commit": "Commitment"},
		ExpressionAttributeValues: map[string]ydbAttr{
			":v1": ydbN(ydbSchemaVersion), ":oldE": ydbN(strconv.FormatUint(old.Epoch, 10)), ":oldD": ydbS(hex.EncodeToString(old.DenyDigest[:])),
			":oldC": ydbS(hex.EncodeToString(old.Commitment[:])), ":nextE": ydbN(strconv.FormatUint(next.Epoch, 10)),
			":nextD": ydbS(hex.EncodeToString(next.DenyDigest[:])), ":nextC": ydbS(hex.EncodeToString(next.Commitment[:])),
		}, ReturnValues: "ALL_NEW",
	}, &result)
	if err != nil {
		return ErrAnchorHold
	}
	confirmed, err := parseYDBItem(result.Attributes, next.Installation, next.Vault)
	if err != nil || confirmed != next {
		return ErrAnchorHold
	}
	return nil
}
