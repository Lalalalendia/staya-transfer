# ADR-0030: remote YDB Document API conditional DENY checkpoint (research)

**Status:** draft / lab / no product authority. Stacked on STY [Draft #47](https://github.com/Lalalalendia/staya-transfer/pull/47), and older #45, #42, #40. Nothing is merged into main or called by the installed Akula. This ADR is a *wire-contract adapter*, **not a deployed trust root**.

## Problem and selected interface

The pre-existing `TrustedDenialAnchor` contract requires a fresh read of the checkpoint and a conditional compare-and-seal. YDB's DynamoDB-compatible Document API documents:

- `GetItem` must send `ConsistentRead: true`; its default is eventually consistent.
- `UpdateItem` supports `ConditionExpression` and `ReturnValues: ALL_NEW`. **Without a condition, UpdateItem may create a missing record**, so this adapter always requires `attribute_exists` for both keys and exact old version/digest/commitment checks.
- Its HTTP endpoint uses `X-Amz-Target: DynamoDB_20120810.GetItem/UpdateItem` and accepts a short-lived IAM `Authorization: Bearer` token. The production constructor pins the HTTPS hostname `docapi.serverless.yandexcloud.net`, forbids redirects, proxy inheritance, HTTP and caller-selected untrusted destinations.

Official references:
- https://yandex.cloud/en/docs/ydb/docapi/api-ref/actions/getItem
- https://yandex.cloud/en/docs/ydb/docapi/api-ref/actions/updateItem
- https://yandex.cloud/en/docs/ydb/docapi/tools/aws-http
- https://yandex.cloud/en/docs/ydb/docapi/tools/aws-sdk/

## Preprovisioned schema and ownership

A separately administered operator must provision a serverless Document API table (for instance `test/epoch`) **before** first use. Exactly one row per namespace is required. The partition key `Installation` (S: lower-case 32-character hex), sort key `Vault` (S: lower-case 32-character hex) and the following attributes are mandatory:

| Attribute | Type | Meaning |
|---|---|---|
| `Installation` | `S` | 16-byte identity |
| `Vault` | `S` | 16-byte identity |
| `Epoch` | `N` | Canonical decimal `uint64`, no leading zeros |
| `DenyDigest` | `S` | Lowercase SHA-256 hex of the **entire DENY floor map** |
| `Commitment` | `S` | Lowercase SHA-256 hex `AKULA_DENY_ONLY_CHECKPOINT_V1` over installation, vault, epoch and digest |
| `SchemaVersion` | `N` | Exactly `1` |

Any unknown/missing attribute, wrong namespace, malformed type/value, incorrect digest commitment, empty row or wrong schema is `HOLD`. No `PutItem`, `CreateTable`, `DeleteItem`, upsert, auto-bootstrapping or positive-permission operation exists. Separate external provisioning of the genesis row is not implemented by this adapter.

## Exact write fence

The `UpdateItem` request includes both pre-existing key checks and `SchemaVersion = 1`, `Epoch = expected`, `DenyDigest = expected digest`, `Commitment = expected commitment`; it updates epoch/digest/commitment to the canonical `next` value with `next.Epoch = expected.Epoch + 1` and distinct digest. Response must contain `ALL_NEW` and be byte-for-byte equivalent to the required next checkpoint. No retry is issued on HTTP error, timeout, stale conditional failure or lost response; all are `HOLD`.

In the existing `AppendOwnerDenyWithAnchor`, the OS-file journal is synced **before** remote CAS. Remote failure after the local append leaves the journal ahead and untrusted until independently reviewed; it is **not** an atomic distributed transaction. A response-loss scenario may have committed on YDB even when the caller sees HOLD. A new **diagnostic-only** read may observe matching state, never authorization or automatic retry.

## Test evidence

Go standard-library implementation in `interop/owner-witness-lab/owner_ydb_docapi.go`, exercised by `owner_ydb_docapi_test.go` using a real local **TLS HTTP test server** that mimics the YDB Document API wire response. Tests check exact requests, strongly consistent `GetItem`, fenced `UpdateItem` with `ALL_NEW`, no implicit create, stale/malformed/foreign/missing record, network/HTTP errors and lost CAS response. The negative falsifier restores both an old correct journal and a matching old correct remote item: this can still pass every cryptographic and consistency check.

GitHub CI executes the tests on Windows and Linux. No cloud credentials, external database or hosted runtime are provisioned. A **local HTTPS mock** is not a true independent source or an authoritative YDB service test.

## P0 / product HOLD gates

1. Independently operated remote principal and actual provisioned YDB serverless database with narrow per-table read/CAS permissions; no Akula desktop credential. Verify short-lived IAM token rotation, expiry and audit. Use only secure runtime credential injection, never GitHub secrets for this lab.
2. Live YDB test with concurrent external processes, `ConsistentRead`, `ConditionExpression` errors, read/response ambiguity, network partitions and server reboot. Confirm no silent recreation after deletion.
3. Explicit adversary model for administrator privileges and provider snapshot restore. **YDB alone does not prevent an authorized DB administrator rolling the table back.** Require separate admin custody, immutable/external audit or hardware-backed monotonic state and verify a real rollback attack is blocked.
4. Bind future **complete positive + negative grant policy**, trusted QUIC identity and broker permissions; current DENY-only commitment is insufficient for grants. Verify real two-machine physical deployment and File Gate separately.

`CONSISTENT_DENIAL_ONLY` never implies `ALLOW`, `APPLIED`, ACK, File Gate write or P2P entitlement. Main and installed Akula remain untouched.
