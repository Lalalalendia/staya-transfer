# ADR-0017 — STY-G2-05h2: real FsStore actor-shutdown witness under OS custody

Parent: [G2-05h issue #21](https://github.com/Lalalalendia/staya-transfer/issues/21) and [G2 #7](https://github.com/Lalalalendia/staya-transfer/issues/7). Depends on **unmerged** G2-05h1 [PR #22](https://github.com/Lalalalendia/staya-transfer/pull/22); this is a STACKED experimental PR, not an independent patch on main.

## Objective

The verified-Bao admission ledger's `admissions_drained()` only proves that cooperative **local permits** ended after an irreversible `stop_admissions`. The pinned `iroh-blobs::FsStore` actor can still own storage resources and background writes. Releasing the exclusive store lock at this point without confirming actor shutdown can admit a second writer too early.

This lab introduces a private, typed wrapper in `interop/fsstore_shutdown_supervisor.rs` which owns BOTH the original `StoreLease` and the actual pinned `FsStore`, and does not expose either raw actor or raw OS lock to import callers.

```text
ActiveFsStore (held StoreLease + real pinned actor + admission ledger)
    | stage() -> authenticated Bao accepted + live non-cloneable permit
    | begin_closing()  [atomic one-way admission close]
    v
ClosingFsStore (same lease + same pinned actor)
    | finish() fails if any permit remains; returns same Closing and its lease
    | finish() calls real FsStore::shutdown().await
    | validate_fence() before and after successful actor shutdown
    v
QuiescentFsStore (private constructor; same lease; actor successfully shut down)
    | inspect physical .data/.obao4; independently verify Bao and journal candidates
    | finish_clean() -> normal OS fd close only; NEVER explicit LOCK_UN
    v
Second process may independently attempt OS ownership + Bao revalidation
```

## Failure and cancellation policy

- Live permit, poisoned ledger, failed physical identity, failed upstream shutdown => **no quiescence witness**. The failing `finish` returns the actual still-owned `ClosingFsStore` so the caller can diagnose/drain or shut down correctly.
- `ActiveFsStore` has a deliberate fail-closed `Drop` guard. If an active actor is abandoned (including an in-flight async shutdown future being cancelled), the OS lease is intentionally **leaked until that process exits**, rather than automatically closing while background actor tasks might still write. This is **not resource-safe for production** and is explicitly a laboratory HOLD behavior until a supervised stop/abort/join path exists.
- Once `FsStore::shutdown` succeeds and the fence is still valid, the actor is dropped and a private quiescence witness is constructed. Clean release then uses normal OS descriptor close, **not `File::unlock()/LOCK_UN`**. An inherited FD can still create temporary `WouldBlock`; the next process must fail closed and may not silently assert progress.
- No registered child-writer inventory/join yet. This stage cannot authorize future explicit unlock when active inherited child writers exist. The unsafe early unlock counterexample remains in blocked [PR #17](https://github.com/Lalalalendia/staya-transfer/pull/17).

## Falsifiable CI contract

- Start *real* pinned release/fork `FsStore` only after acquiring the cooperative OS owner.
- Import an independently authenticated 16-KiB-aligned Bao range with a live `InflightPermit`.
- Close new admission; clones cannot re-admit. Attempt to finish while permit lives must fail and retain OS custody. An independent second `StoreLease::acquire` must return `WouldBlock`.
- Drop the permit; finish must call the real upstream `FsStore::shutdown`; only after success and identity checks may a private `QuiescentFsStore` exist. It still holds OS custody.
- Read the actual sparse `.data` and `.obao4` and verify Bao bytes against a trusted BLAKE3 root. No journal candidate is minted by mere actor shutdown.
- Cleanly drop quiescent custody (no explicit unlock); a second owner may acquire and reopen the actual FsStore, revalidate the same Bao bytes and cleanly shut down.
- Exact-head Linux/Windows custody, Rust contracts, **pinned release/fork interop**, rustfmt and Clippy. No dependency or Cargo.lock drift. CI success is mandatory before accepting either stacked PR.

## Exclusions / next stage

This is NOT `G2-05h` completion, a full child-writer join, proof that `FsStore::shutdown` covers power-loss, a verified post-SIGKILL range skip, physical disk quota, enforced all-path adversarial ownership, or any Akula File Gate permission. The intentional lock leak on abandoned actors is operationally unacceptable in a production daemon.

The next separate step must register/join all authorized child writers (and own explicit cancellation/abort semantics), then replace the laboratory leak-on-abandon safety measure with bounded supervised shutdown. Only after that may clean explicit OS unlock be considered. Keep G2-06/G3 blocked.
