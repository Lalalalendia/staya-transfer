# ADR-0014 — STY-G2-05f: bounded real FsStore import admission (experimental)

Canonical task: [G2 #7](https://github.com/Lalalalendia/staya-transfer/issues/7); master plan: [STY-MASTER-PLAN-02](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd).

## Scope

This extends merged G2-05c local resource accounting into the **actual pinned release/fork FsStore** import test. A process-local `SharedAdmission` holds an Arc/Mutex ledger, and each non-cloneable `InflightPermit` reserves a complete resource request until Drop, including unwind/cancel/error exits. The ledger mutex is never held during network or disk I/O. Poisoned ledgers deny admission. Only trusted local limits can configure this process-local budget.

The bounded test adapter checks the G2-03 OS `StoreLease` identity fence before admission and after actual upstream FsStore import. It reserves one object slot, four *planned* backing-file handles, and logical bytes = requested decoded range + received wire bytes. It rejects insufficient admission, cancelled requests, invalid Bao proof and a second competing logical reservation before adding a checkpoint. The import is the real G2-02 `Blobs::import_bao_bytes`, independently verified against BLAKE3 root. After clean FsStore shutdown it independently validates physical Bao on actual sparse files; no `read_candidates` is published merely because the import was admitted.

Existing interop release/fork Cargo.lock files and the upstream wire/Bao compatibility tests remain unchanged. The added test runs in the existing release/fork CI and the custody ledger has separate thread-concurrency unit tests on Linux and Windows.

## Important limitations

* This is **only an in-flight logical admission budget**. It does NOT cap on-disk FsStore bytes, redb storage, OS open file descriptors, memory allocator usage, or available disk space. It does not claim ENOSPC handling or cancellation *inside* an active FsStore actor.
* A cancel racing with actor import may leave uncommitted partial bytes. The adapter returns error with the reservation released and *does not* create a checkpoint or skip authorization; a future recovery process must still verify physical Bao.
* Locking is cooperative only; PR #17 is separately investigating Linux reacquisition flakiness. This PR does not modify OS lock implementation or assert that it is fixed.
* No Akula File Gate, Vault, user files, S3, relay, durable APPLIED, Windows directory durability or full G2-05/G2-06 acceptance.
* Remaining work: enforce real backend disk/FD quotas or fail-closed supervisor, exercise actual ENOSPC and cancellation injection, Windows real FsStore TerminateProcess, multi-point crash injection, then independent G2-06 acceptance.
