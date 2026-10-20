# ADR-0028 — owner DENY checkpoint and non-atomic crash boundary (research)

**Status:** draft, isolated test lab, NOT a deployed trusted anchor or access authorization. Depends on STY Draft [#40](https://github.com/Lalalalendia/staya-transfer/pull/40) and [#42](https://github.com/Lalalalendia/staya-transfer/pull/42); relates to Akula [#467](https://github.com/Lalalalendia/Akula/pull/467).

## Problem and trust model

A valid old owner journal can be restored and the existing TLS/Ed25519 owner can sign its stale state with a fresh challenge. A local checksum, file lock, signature, or persistent SQL transaction cannot prove that the *owner's own storage* has never been rolled back. This is reproducible in the earlier `TestOwnerLedgerSignerCannotRecognizeItsOwnValidOldSnapshot` test.

This PR adds a **port** `TrustedDenialAnchor` with two abstract operations: `Read` (fresh, linearizable, independently authenticated) and `CompareAndSeal` (exclusive, durable, monotonic CAS). The only implementation here is an in-memory **test double**. The interface is **not** an independent trust root and MUST NOT be registered in a shipped component. Every caller must separately validate the real backend's identity, authorization, nonrollbackability, durability, reset rules and governance. The lab makes no claim against compromise/rollback of the test double or of a real anchor's administrator.

The `DenialCheckpoint` binds installation (16 bytes), vault (16 bytes), global epoch and SHA-256 of the **complete sorted denial-floor map** to a domain-separated commitment. It deliberately does **not** bind future positive grants. Production must expand this protocol to the **complete positive + negative policy** before any endpoint or file permissions exist.

## Fail-closed read

`ReadAnchoredDenialHead` opens the same pre-existing file, holds the OS-exclusive file lock, replays every journal record, obtains a fresh backend checkpoint, and compares the **entire** canonical checkpoint. Missing backend, I/O error, wrong namespace, no commitment, invalid hash, outdated/advanced epoch, same epoch with another digest, cancelled request and torn journal all result in `ErrAnchorHold`. No automatic repair, clock-based expiry fallback or unsigned cached checkpoint is allowed. `AnchoredDenialLoader` can replace the lab's unanchored Loader for **DENIAL-ONLY mTLS diagnostics**; it cannot issue a grant.

## Two-phase ordering and crash matrix

`AppendOwnerDenyWithAnchor` holds the same OS lock across full local replay and fresh backend read, then writes one DENY record, `File.Sync`, same-handle full readback, backend `CompareAndSeal(expected,next)` and a second fresh backend read. The shared low-level writer is refactored into `appendDenyLocked` so anchored and unanchored test helpers produce the **same binary records** and release no second file handle mid-CAS.

This is deliberately **not** an atomic cross-system transaction. Local and external state can diverge after crash, error, timeout or adversarial intervention. The result table is:

| Owner journal | Independent checkpoint | Diagnostic result | Automatic recovery |
| --- | --- | --- | --- |
| Same epoch and same digest | Matching namespace, epoch, digest and commitment | `DENIAL_SNAPSHOT_CONSISTENT` only; no permit | N/A |
| Older / restored | Newer | `HOLD` | Never |
| Ahead after local fsync | Older / CAS unavailable | `HOLD` | Never |
| New backend seal before local durable replay | Ahead | `HOLD` | Never |
| Same epoch, different denial map | Divergent | `HOLD` | Never |
| Anchor lost, unreadable, identity wrong or unavailable | Unknown | `HOLD` | Never |
| CAS may have succeeded but acknowledgment was lost | Unknown at call return | `HOLD` return | Later fresh diagnostic allowed; no grant |

An operator-controlled recovery ceremony must determine which checkpoint and record are authoritative and preserve all revoked floors. Neither replaying a stale grant nor silently truncating torn logs is acceptable. This code does not implement that ceremony. A real power cut is not demonstrated by process termination tests; Windows and Linux runner `Sync` tests are not storage/hardware durability proofs.

## Verified automated scope

- Correct anchor round-trip, same epoch differing map, whole valid old journal replay (negative falsifier), namespace/commitment mismatch, unavailable/absent anchor, cancelled request.
- Ledger ahead of anchor, anchor ahead of ledger, CAS call error before seal, successful CAS with lost response, cold readback and refusal to retry a conflicted epoch.
- Only one winner for concurrent local anchored CAS; existing **separate OS-process** journal test remains part of the combined suite.
- Real TLS 1.3 client/server/Ed25519 laboratory handler signs a denial checkpoint only if fresh external *test* anchor matches; unavailable anchor makes HTTP sign operation fail (no fallback).
- Rust/Staya runtime, Akula Core/native, File Gate, QUIC, APPLIED, ACK, grants and installed app: **no modifications**.

## Production gate still missing

1. Choose and implement a **real independent monotonic backend**, including a hardware-backed or separately administered owner. Verify nonrollback and CAS across reboot/rollback attempts, signer custody, certificate pinning and independent authority. A TPM NV `counter` can only increment; TPM NV `extend` instead accumulates a digest. These are distinct primitives, and Windows TBS does not itself provide transactional application state: see [tpm2-tools NV attributes](https://github.com/tpm2-software/tpm2-tools/blob/master/man/common/nv-attrs.md), [TPM NV extend](https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_nvextend.1.md), and [Microsoft TBS](https://learn.microsoft.com/windows/win32/tbs/tpm-base-services-portal).
2. Bind **complete positive and negative policy bytes** to an externally verifiable root, not merely denial floors. Validate identity scope, key rotation, owner migration, index exhaustion, owner reset and power-loss recovery.
3. Prove a second physically isolated host, signed provenance and authenticated transport, then wire actual Akula Broker / File Gate authorization with revocation recheck. No test success implies permission to write.

**Release:** HOLD. This PR intentionally contains **no production anchor provider** and no grant-producing code.
