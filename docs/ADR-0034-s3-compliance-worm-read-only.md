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
2. `ListObjectVersions` for the exact pinned object key; inspect **every version**, not only `IsLatest=true`. If a delete marker exists, listing is truncated/ambiguous, the version count is outside **1..128**, any version is missing, or a read fails, return `HOLD`. Get the exact VersionID from the list, then request each object's payload and `GetObjectRetention` with that VersionID. Require COMPLIANCE and at least **7 days of remaining retention** for every record.
3. Interpret exact canonical JSON signed record `akula-deny-worm-v1` with `Installation`, `Vault`, canonical decimal `Epoch`, `DenyDigest`, `Commitment`, `Previous` SHA-256 and Ed25519 `Signature`. The signer public key comes from separately pinned operator configuration, **never the object**. Signatures are domain-separated: `AKULA_DENY_WORM_VERSION_V1\0` over the canonical namespace, epoch, DENY map SHA-256, checkpoint commitment and previous record hash. The record hash binds the signed bytes and signature. The verifier does not accept unknown fields, duplicate content or variant JSON encoding.
4. Sort the signed records by epoch. Require exactly one epoch **0 genesis**, then **all consecutive epochs** without forks or gaps, with each `Previous` matching the preceding record hash. Require exactly one `IsLatest=true` pointing at the highest epoch. Read the version list a second time after loading all bodies and fail if its complete metadata snapshot changed (best-effort TOCTOU defense, not a transaction).
5. Compare the highest verified WORM checkpoint to the supplied already-fresh YDB checkpoint, including namespace, epoch, complete **DENY-only** floor digest and domain-separated commitment. Only identical checkpoints give a **diagnostic consistency result**, **never** an access grant.

All S3 API calls are read-only: `get-bucket-versioning`, `get-object-lock-configuration`, `list-object-versions`, `get-object-retention`, `get-object` with explicit VersionID. Endpoint is pinned to `https://storage.yandexcloud.net`. The AWS CLI uses a separate local operator's AWS_PROFILE or temporary environment credentials. No cloud IAM credentials are committed to GitHub or output in CI logs.

## Live operator gate — opt-in only

Provision **separately** before running: (a) a versioned locked S3 bucket with default COMPLIANCE retention, (b) a fixed object key whose versions contain signed consecutive epoch 0..N records, (c) a **read-only** operator identity able to list versions and query retention/body without write permissions, (d) a pinned Ed25519 owner public key, and (e) the expected checkpoint from a fresh YDB read. Neither this PR nor normal GitHub Actions provisions or writes any of those resources.

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
export STY_WORM_DENY_DIGEST_HEX='independently-read-32-byte-deny-digest-in-hex'
# Configure AWS_PROFILE/temporary S3 credentials separately; do not place keys in flags or GitHub secrets.
go test -count=1 -run '^TestObjectLockLiveReadOnlyPreflight$' -v .
```

If no `STY_WORM_LIVE_READ=1`, this integration test explicitly **SKIPs**. The regular CI tests a mock AWS CLI and locally signed version records; it is not live Yandex Object Storage evidence. Live success must be recorded with the exact version IDs, signed public-key fingerprint, COMPLIANCE retention expiry and separately operated account provenance, **not credential values**.

## Unresolved attacks / production HOLD

- **Expiry/deletion:** even genuine COMPLIANCE retention expires. If privileged administrators later delete the newest version after expiry, an internally valid old genesis may again appear current. A deliberately negative test shows this. Production requires a lifetime-bounded threat model **and an independent retained high-water lower bound** (or continuously renewed externally anchored history). This preflight does not implement either.
- **Shared administrator/key:** one party able to restore the YDB and also control or delete the protected history once retention expires defeats it. A signed record does not prove independent custody. A stolen owner signing key may create an unauthorized *new* version; the verifier refuses inconsistent forks but cannot prevent denial of service.
- **S3 listing freshness:** repeating `ListObjectVersions` is only a best-effort detection of concurrent updates. The S3 and YDB snapshots are not an atomic distributed transaction. Version-history completeness, service consistency and operator authorization must be validated on real infrastructure.
- **Partial CAS:** if the two authorities or the append-only audit record diverge after a crash, the result stays `HOLD`. There is no automatic repair, re-sign, retry, fallback to latest or manual reset implementation.
- **Policy completeness:** these records cover DENY floors only, not positive grants, peer identities, QUIC entitlements, File Gate rights or trusted installer provenance. No signed File Gate grants are implemented.

**Acceptance for this PR:** Linux/Windows Go tests, Linux race/vet/gofmt, strict new-file scope and optional live read-only operator test as an **unmet separate gate**. Production `P0 antirollback` remains OPEN until independent IAM/custody, actual locked S3 versions and expiry/restore attack have been demonstrated on two separate operational trust domains.
