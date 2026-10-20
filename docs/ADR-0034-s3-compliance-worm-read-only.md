# ADR-0034: S3 COMPLIANCE Object Lock read-only DENY high-water preflight

**Status: Draft / isolated research. NOT a deployed trust root.** Stacked on STY #60 (two-authority DENY CAS). No code in the shipped Akula, Staya Rust, File Gate or production installer changes. **HOLD** for all grants, file writes, APPLIED and ACK.

## Why S3 version retention matters

Yandex Object Storage implements immutable *object versions* in Object Lock **COMPLIANCE** mode, provided that versioning and Object Lock are enabled. Even an administrator cannot overwrite or delete a locked version while its retention has not expired. However, another version may still be uploaded under **the same key**. The `GetObject` response for the current/latest key **is not** evidence of the highest historical DENY epoch. Governance mode can be bypassed by storage admins and is explicitly refused.

Official references (last verified October 2026):
- https://yandex.cloud/en/docs/storage/concepts/object-lock
- https://yandex.cloud/en/docs/storage/operations/objects/edit-object-lock
- https://yandex.cloud/en/docs/storage/s3/api-ref/bucket/listObjectVersions
- https://yandex.cloud/en/docs/storage/s3/api-ref/object/getobjectretention

## Read-only verifier: RN-4E1b-03c1c1

`owner_worm_audit.go` implements an entirely read-only AWS CLI-backed S3 snapshot inspection. It is **not** `TrustedDenialAnchor` and it does not expose `CompareAndSeal`.

1. Confirm `GetBucketVersioning.Status=Enabled` and `GetObjectLockConfiguration.ObjectLockEnabled=Enabled`, and require **default COMPLIANCE** retention. These are preflight configuration checks; actual retention must be checked for **each version**.
2. `ListObjectVersions` for the exact pinned object key; inspect **every version**, not only `IsLatest=true`. The S3 response must explicitly contain **`IsTruncated=false`**: omitting the field is *unknown completeness* and returns `HOLD` (not Go's zero-value false). If a delete marker exists, listing is truncated/ambiguous, the version count is outside **1..128**, any version is missing, or a read fails, return `HOLD`. Get the exact VersionID from the list, then request each object's payload and `GetObjectRetention` with that VersionID. Require COMPLIANCE and at least **7 days of remaining retention** for every record.
3. Interpret exact canonical JSON signed record `akula-deny-worm-v1` with `Installation`, `Vault`, canonical decimal `Epoch`, `DenyDigest`, `Commitment`, `Previous` SHA-256 and Ed25519 `Signature`. The signer public key comes from separately pinned operator configuration, **never the object**. Signatures are domain-separated: `AKULA_DENY_WORM_VERSION_V1\0` over the canonical namespace, epoch, DENY map SHA-256, checkpoint commitment and previous record hash. The record hash binds the signed bytes and signature. **Canonical JSON is now enforced byte-for-byte**: encode `wormSignedRecord` as compact UTF-8 JSON with the declared field order (`schema`, `installation`, `vault`, `epoch`, `deny_digest`, `commitment`, `previous`, `signature`) and Go `encoding/json` string encoding semantics. Other writers must emit exactly this protocol serialization. Duplicate keys, field reorderings, alternate whitespace/escapes and trailing newlines are `HOLD`, even if the decoded Ed25519-signed checkpoint would be the same; otherwise two JSON parsers could disagree over the meaning of a signed record.
4. Sort the signed records by epoch. Require exactly one epoch **0 genesis**, then **all consecutive epochs** without forks or gaps, with each `Previous` matching the preceding record hash. Require exactly one `IsLatest=true` pointing at the highest epoch. Read the version list a second time after loading all bodies and fail if its complete metadata snapshot changed (best-effort TOCTOU defense, not a transaction).
5. Before any S3 calls, read the actual YDB record through a read-only `DenialAnchorReader` (the live probe constructs `YDBDocumentDenialReader` with `GetItem ConsistentRead=true`) and require the operator's exact expected checkpoint. Verify the retained WORM chain, then **reread YDB** and require the identical checkpoint. Neither this bracketing nor two S3 listings form an atomic cross-service snapshot; any intervening difference is `HOLD`.
6. **An independently pinned minimum high-water checkpoint is mandatory** for the integrated preflight. It includes Installation, Vault, global epoch, full DENY-floor digest and computed commitment, and must match the **actual signed WORM version at that epoch**. The floor must never be derived from the YDB row or Object Storage listing under examination. Advance the separately protected pin after every owner-approved transition, under independent custody; a stale pin cannot detect a deleted newer tail. The new function `ObserveYDBAgainstWORMWithPin` checks this requirement. Existing `ObserveYDBAgainstWORM` remains explicitly **unanchored, diagnostic-only**, useful only for negative falsifiers.
7. Only matching pinned minimum, current WORM state and two fresh YDB reads give a **diagnostic consistency result**, **never** an access grant.

**Regression evidence (RN-4E1b-03c1c1 hardening):** before the fix, the original verifier returned a diagnostic success for a mock S3 reply omitting `IsTruncated` and for four JSON variants (a duplicate `schema` key, reordered fields, leading space, trailing newline). The new regression tests first reproduced those erroneous successes, then confirmed all variants `HOLD`. The code still only checks synthetic AWS CLI output until the separate live operator preflight is run.

All S3 API calls are read-only: `get-bucket-versioning`, `get-object-lock-configuration`, `list-object-versions`, `get-object-retention`, `get-object` with explicit VersionID. Endpoint is pinned to `https://storage.yandexcloud.net`. The AWS CLI uses a separate local operator's AWS_PROFILE or temporary environment credentials. No cloud IAM credentials are committed to GitHub or output in CI logs.

## Live operator gate — opt-in only

Provision **separately** before running: (a) a versioned locked S3 bucket with default COMPLIANCE retention, (b) a fixed object key whose versions contain signed consecutive epoch 0..N records, (c) a **read-only** operator identity able to list versions and query retention/body without write permissions, (d) a pinned Ed25519 owner public key, and (e) a current read-only YDB endpoint, database/table and IAM token file, (f) the exact expected checkpoint separately approved by the operator, and (g) a **separately retained, independently protected minimum epoch and DENY digest**, updated after each accepted DENY event. A floor copied from current YDB/S3 is **not** an antirollback pin. Neither this PR nor normal GitHub Actions provisions or writes any of those resources.

Run from a **controlled operator workstation**, never in ordinary hosted CI:

```bash
cd interop/owner-witness-lab
export STY_WORM_LIVE_READ=1
export STY_WORM_BUCKET='independently-owned-locked-bucket'
export STY_WORM_KEY='audit/revocation.json'
export STY_WORM_OWNER_PUBLIC_KEY_HEX='operator-pinned-32-byte-ed25519-public-key-in-hex'
export STY_WORM_INSTALLATION_HEX='16-byte-installation-identity-in-hex'
export STY_WORM_VAULT_HEX='16-byte-vault-identity-in-hex'
export STY_WORM_EXPECTED_EPOCH='0'
export STY_WORM_DENY_DIGEST_HEX='operator-approved-current-32-byte-deny-digest-in-hex'
# Pinned separately by the independent owner and stored outside YDB/S3;
# these MUST NOT be read back from the very two sources being inspected.
export STY_WORM_PINNED_MIN_EPOCH='0'
export STY_WORM_PINNED_MIN_DIGEST_HEX='independently-pinned-32-byte-deny-digest-in-hex'
# Read-only YDB IAM token from a PRIVATE (0600) file, never flags / GitHub CI.
export STY_WORM_YDB_ENDPOINT='https://docapi.serverless.yandexcloud.net/ru-central1/folder/database'
export STY_WORM_YDB_TABLE='test/epoch'
export STY_WORM_YDB_IAM_TOKEN_FILE='/secure/operator/ydb-viewer-iam-token'
# Configure AWS_PROFILE/temporary S3 credentials separately; do not place keys in flags or GitHub secrets.
go test -count=1 -run '^TestObjectLockLiveReadOnlyPreflight$' -v .
```

If no `STY_WORM_LIVE_READ=1`, this integration test explicitly **SKIPs**. With the opt-in enabled, absent pin/YDB configuration is a hard failure (not a mock PASS); the test reads **actual live YDB twice**, before and after the real read-only S3 inspection. Setting the pinned minimum to epoch 0 is appropriate *only before any owner-approved revocation has happened*. A minimum equal to today's YDB value copied from YDB at runtime is not independent trust. The regular CI tests a mock AWS CLI and locally signed version records; it is not live Yandex Object Storage evidence. Live success must be recorded with the exact version IDs, signed public-key fingerprint, COMPLIANCE retention expiry and separately operated account provenance, **not credential values**.

## Unresolved attacks / production HOLD

- **Expiry/deletion:** even genuine COMPLIANCE retention expires. If privileged administrators later delete the newest version after expiry, an internally valid old genesis may again appear current. The independently supplied pinned minimum detects rollback **only if separately protected and actually advanced**. This PR validates its existence and exact match within the signed chain, but **does not implement storage, updates, access control, or rollback protection of the pin**. A malicious administrator able to overwrite the pin along with YDB/S3 still defeats it. Production requires a threat-horizon retention policy and independently administered, durable minimum storage.
- **Shared administrator/key:** one party able to restore the YDB and also control or delete the protected history once retention expires defeats it. A signed record does not prove independent custody. A stolen owner signing key may create an unauthorized *new* version; the verifier refuses inconsistent forks but cannot prevent denial of service.
- **S3/YDB read freshness:** repeating `ListObjectVersions` and strongly consistently reading YDB before/after S3 is only a best-effort detection of concurrent updates. The S3 and YDB snapshots are not an atomic distributed transaction. Version-history completeness, service consistency and operator authorization must be validated on real infrastructure.
- **Partial CAS:** if the two authorities or the append-only audit record diverge after a crash, the result stays `HOLD`. There is no automatic repair, re-sign, retry, fallback to latest or manual reset implementation.
- **Policy completeness:** these records cover DENY floors only, not positive grants, peer identities, QUIC entitlements, File Gate rights or trusted installer provenance. No signed File Gate grants are implemented.

**Acceptance for this PR:** Linux/Windows Go tests, Linux race/vet/gofmt, strict new-file scope and optional live read-only operator test as an **unmet separate gate**. Production `P0 antirollback` remains OPEN until independent IAM/custody, actual locked S3 versions and expiry/restore attack have been demonstrated on two separate operational trust domains.
