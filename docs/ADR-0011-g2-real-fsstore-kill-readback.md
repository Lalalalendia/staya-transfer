# ADR-0011 — STY-G2-05a: real FsStore process-kill observations (narrow lab gate)

**Scope:** STY-G2 [issue #7](https://github.com/Lalalalendia/staya-transfer/issues/7), after accepted G2-04a [#11](https://github.com/Lalalalendia/staya-transfer/pull/11) and G2-04b [#13](https://github.com/Lalalalendia/staya-transfer/pull/13). This is not the full G2-05 crash matrix, not a power-loss durability proof, and not an Akula integration.

## Why the test is separate

The pinned `iroh-blobs` FsStore warns that partial writes may not survive abrupt death. A successful `import_bao_bytes` indicates actor acceptance, not durable storage. A valid BLAKE3/Bao proof over received bytes does not imply that the bytes and outboard are still readable after process termination. Conversely, a persisted bitmap or checkpoint claim must not authorize a skipped transfer range without a new physical Bao audit.

## Two independent-process scenarios

The same test executable starts an actual **child OS process** using pinned release or fork FsStore and the real Bao staging adapter; the parent does not share the store actor or Rust memory.

1. **Uncommitted:** under the existing OS-exclusive `StoreLease`, the child imports one 16 KiB-aligned partial Bao range into a live FsStore and signals readiness **without `shutdown` or checkpoint publication**. The parent verifies that another independent owner is denied, then forcefully kills the child (SIGKILL on Linux, TerminateProcess on Windows). On reacquiring ownership, checkpoint inventory must be empty, regardless of whether partial bytes happened to survive. A physical sparse Bao/outboard audit reports actual recovery evidence but does not grant a skipped range.
2. **Checkpointed (Unix):** the child performs clean FsStore shutdown, four-file/directory barriers, independent root-bound physical Bao validation, and canonical G2-04a checkpoint publication; only then does the parent kill it. A new process must acquire custody, observe exactly one checkpoint candidate and independently revalidate the original range against physical data and Bao. The candidate is **never** a verified range by itself.
3. **Checkpointed (Windows):** the G2-04b barrier is explicitly unsupported. The worker must not publish a durable checkpoint candidate. The parent still kills and reopens the real store, but does not claim crash-safe resume.

In all scenarios, the restarted process calls real `FsStore::load` and obtains backend status strictly for diagnostics. That backend bitmap/status is **not** a transfer authorization. Test-only private temporary files are cleaned up after both subprocesses exit.

## CI and release constraints

G2-05a initially runs on Linux in the existing pinned release/fork `interop` jobs using their **existing immutable Cargo.lock and `--locked`**. This avoids an additional broad workflow while checking both backends and preserving previous QUIC GET regression tests. Windows process failure-injection with real FsStore is an independent follow-up gate; the standalone Windows lock/custody tests are not its substitute.

Still required for **G2-05 full acceptance**: kill at each import, outboard, data, sync, journal temporary-file, rename and directory-barrier crash point; windows real FsStore kill harness; missing/corrupt outboard; disk-full/fd/object/journal quotas and cancellation; redb transaction durability; hostile same-inode writers; physical security of pathname opens; power-loss and storage-controller semantics. Do not start STY-G3 or mutate Akula user data.
