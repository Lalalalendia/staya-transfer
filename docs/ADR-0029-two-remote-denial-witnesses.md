# ADR-0029 — two independently pinned online DENY witnesses (read-only)

**Status:** Draft experiment. Proposed only on top of [STY #45](https://github.com/Lalalalendia/staya-transfer/pull/45). Never authorize P2P, File Gate or installed Akula.

## Why and trust boundaries

A single owner-side file plus an owner-supplied signing key can return fresh Ed25519 signatures for **replayed historical denial state**. A single compromised remote witness may do the same. The next bounded step requires two independent identities (TLS server leaf SPKI **and** Ed25519 signing key), two distinct URLs, and two fresh signed 32-byte challenge responses for the same `(Installation, Vault)` namespace. Every read is a 2-of-2 equality check on the full canonical `(epoch, deny-floor digest)` checkpoint. One stale/mismatched/offline/forged signer causes `HOLD`; no fallback to 1-of-2, no local cache, no automatic synchronization.

**Independence is not established by having two keys or OS processes.** Acceptance with real machines requires distinct administrative domains, credential owners, host keys, storage custody, deployment attestations, independent fresh reads and strict permissions that prevent the original Akula owner from modifying either witness. CI only proves separate processes within a single runner, explicitly not two independent hardware roots.

## Least authority by construction

Old interface `TrustedDenialAnchor` served reads and mutating seals. Split into:

- `DenialAnchorReader`: only authenticated fresh `Read`. Accepted by `ReadAnchoredDenialHead` and `AnchoredDenialLoader`.
- `TrustedDenialAnchor`: extends the reader with `CompareAndSeal`. Still required by `AppendOwnerDenyWithAnchor`. No wrapper may turn a read-only refusal into an authority to append; that would write the journal BEFORE discovering that a seal is unavailable.

`ReadOnlyRemoteQuorum` deliberately does **not** implement `CompareAndSeal`: Go's static type checker prevents this reader from being passed to the writer. It also keeps the `Handler` read-only; there is no remotely reachable mutation API.

## Protocol

Each `Client.FetchHead()` performs TLS 1.3 chain/hostname verification, pinned remote TLS-SPKI, mTLS client authentication, Ed25519 verification over the canonical witness payload, a fresh randomly generated 32-byte nonce, exact namespace matching and no redirects or response caching. The quorum rejects duplicate URL, duplicate TLS pin, duplicate Ed25519 signing key, pathful/credential-bearing/non-HTTPS URLs, cancelled contexts and any missing response. Two remote calls run concurrently with bounded HTTP timeouts. Responses must be bitwise identical and a domain-separated `DenialCheckpoint` is computed **after** matching both.

The verdict `CONSISTENT_DENIAL_ONLY` means only that the current local DENY-floor state matches both current signed remote states. It NEVER becomes a grant. This code path does not implement owner CAS, grants, migration, recovery or file writes.

## Tests and negative falsifier

- Real TLS client/server for two independent signers; matching state returns only a read-only diagnostic.
- One witness advanced and the other old, one unavailable, one with wrong signature, same epoch with different deny map, rolled-back local ledger, foreign namespace, cancelled context and duplicate witness identities: all `HOLD`.
- Two **separate OS processes** with distinct CA/signing key and individually loaded head files. One process's on-disk head changes; a new read detects the mismatch without cached successful state.
- **Deliberate negative security test:** if BOTH independently signed remote files and the owner local file are replaced with matching valid old snapshots, 2-of-2 can accept the old state again. Therefore this is NOT a nonrollbackable source yet. Production requires independently protected monotonic storage (for example remote strongly consistent CAS, controlled write privileges, immutable audit) and a threat model excluding compromise of both independent custodians. Compromised owners with access to both remote witness files remain a release blocker.

## Next milestones

1. Provision a remotely operated strongly consistent CAS backend with a protected preinstalled checkpoint and restricted separate principal/administrator. Validate `Read` linearizability, writer identity, no destructive overwrite and persistence after remote reboot. A DB conditional update alone cannot defend against a privileged remote admin rolling back the DB; separate custody, immutable history/audit or a hardware-rooted counter still matter.
2. Promote a reviewed **separate mutating provider** to `TrustedDenialAnchor` only after recovery analysis, replay-proof credentials and external crash tests. Read-only quorum must remain non-authorizing.
3. Commit to the *whole future grant + denial policy*, not only DENY-floor map; bind actual QUIC peer and Vault IDs before any file operation.
4. Acceptance on two truly independent hosts with compromised-owner and single-remote-witness rollback exercises; keep File Gate, P2P positive grants, APPLIED and ACK disabled.
