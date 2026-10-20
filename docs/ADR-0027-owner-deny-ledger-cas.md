# ADR-0027: owner-side deny-only persistent CAS journal (research, not authoritative)

**Status:** draft / lab / no product grants. Stacked on STY [PR #40](https://github.com/Lalalalendia/staya-transfer/pull/40); related Akula [#460](https://github.com/Lalalalendia/Akula/pull/460), [#464](https://github.com/Lalalalendia/Akula/pull/464), [#467](https://github.com/Lalalalendia/Akula/pull/467).

## Scope / hard prohibition

Implement a second independent *owner-side* test component. All new source is in `interop/owner-witness-lab` (standalone Go standard-library module) and a CI workflow. It is NOT linked into Staya Rust, Akula, installer, QUIC or File Gate. `AppendOwnerDeny` is an **owner-local** function that records only DENY advances. It has no Allow, Enroll, P2P receipt, write-to-user-files or APPLIED implementation. The signed network `Handler` accepts read-only `POST /v1/head`, never mutations.

## Binary contract

Pre-existing immutable-identity journal path, expected installation `[16]byte` + vault `[16]byte` independently supplied by the caller. Header: 8-byte `AKOLG01\0` magic, installation ID, vault ID, reserved 8 zero bytes (48 bytes). Each of up to 4,096 fixed 112-byte records contains strictly increasing global sequence, replica ID, old/new monotonic floor (`old + 1`), previous SHA-256 chain link, only DENY opcode `1`, reserved zero padding, SHA-256 record digest with domain separation. Fully replay bounded bytes for every read/update. If wrong type, missing, larger than maximum, truncated, altered, bad magic, wrong installation/vault, duplicate ordering, unrecognized opcode or epoch/floor mismatch: `HOLD`. The SHA-256 chain is **not** authenticated and never resists full-file replay by a privileged operator.

## Concurrent OS-process CAS / durability model

- Open existing file with read/write, **no create/no truncate**. Reject symbolic links on `Lstat`; after opening and locking require the pathname and opened handle still refer to the same file. Real installer must protect *all* writable ancestor directories and service identity. Research does not prove ancestor custody or hostile-administrator resistance.
- Linux: kernel `flock(LOCK_EX|LOCK_NB)` with bounded retry. Windows: `LockFileEx` exclusive byte-range lock (including space beyond max file size) with `FAIL_IMMEDIATELY` and bounded retry. The locks serialize **cooperating operations on the same file identity**, not malicious pathname replacement, root/admin writes or restore of valid snapshots.
- Under unchanged lock: replay *all* records, compare `(expectedGlobal, expectedReplicaFloor)`, append DENY record, `File.Sync()`, reread and revalidate all bytes and the new complete state on **the same handle**. A partial write or unknown disk state never truncates/reinitializes/repairs itself. This proves a bounded process test contract, **not** power-loss durability on all filesystems.
- For network use, `LedgerOwnerLoader` bridges validated denial head to existing TLS/Ed25519 signed witness Handler, still only `CONSISTENT_DENIAL_ONLY` or `HOLD`.

## Acceptance and negative falsifiers

Automated tests on both Windows 2022 and Ubuntu 24.04 must prove correct read/replay, independent replica floors, stale global/floor refusal without writes, wrong installation/vault, missing/corrupt/truncated/oversized files, cold reopen, real two-OS-process barrier with exactly **one success (0)** and **one stale CAS failure (77)**, child process exiting after torn write and subsequent cold-reopen HOLD, TLS signer live-reloading the journal after revoke, loss of owner denying operations.

**Critical negative test**: replacing the *entire owner ledger* with an old perfectly well-formed snapshot makes a cryptographically fresh signed owner response match old local data. This counterexample is intentional. A correct SHA-256 chain + TLS + signer + CAS does **not** secure the owner itself from rollback. Never turn consistency into grant authority.

## Mandatory next gating items

1. Independent monotonic owner witness under trusted machine ownership (or TPM/platform monotonic anchor), proven non-rollbackable against the agreed adversary. Pair canonical digest of **the entire future positive + negative policy state** and installation/vault identity with the anchor, not just sequence.
2. Deploy an authenticated, dedicated owner on a second host and physically verify provenance, key custody, OS namespace ACLs, and signed installer; external CA and signing keys in tests are disposable, not credentials.
3. Define safe recovery for `journal ahead of anchor`, `anchor ahead of journal`, partial/power-loss effects and owner migration. No automatic rollback, no grant reuse on timeouts or divergence.
4. Only afterward integrate with actual Akula Windows Broker / authenticated QUIC channel owner / File Gate guarded write / receipt and two-machine acceptance. `APPLIED`, ACK, P2P positive policy and product write stay **HOLD**.

This experiment is valid as a concurrency and recovery building block ONLY. It is not anti-rollback production authority.
