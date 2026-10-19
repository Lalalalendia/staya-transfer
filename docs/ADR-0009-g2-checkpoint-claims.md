# ADR-0009 — STY-G2-04a: immutable checkpoint *claims*, crash-fail-closed reopen

Canonical requirement: [STY-G2 issue #7](https://github.com/Lalalalendia/staya-transfer/issues/7). Overall plan: [STY-MASTER-PLAN-02](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd). Parent main includes [G2-02](https://github.com/Lalalalendia/staya-transfer/pull/9) and [G2-03](https://github.com/Lalalalendia/staya-transfer/pull/10). This is the **metadata protocol**, not integration into Akula Sync or a durability receipt for FsStore bytes.

## What is implemented

The isolated Rust 1.91+ `custody/checkpoint` module requires an actual existing `StoreLease`; there is no public API to write a checkpoint by naming a peer-provided filesystem path. It serializes fixed-size, versioned records of the **locally trusted** BLAKE3 root, exact total object size, pinned 16 KiB Bao storage profile, one aligned byte range and an increasing generation. A BLAKE3 checksum detects torn and accidental corrupted *metadata only*; it is neither a keyed MAC nor a content-Bao proof.

- Maximum 128 immutable generations; fixed 108-byte records; no attacker-controlled allocation based on a record length or an unlimited number of entries.
- Create a new temporary file with `create_new`, write record, `sync_all`, close, rename on the same directory to a **new sequence filename** (no overwrite of an existing “current” record).
- On Unix, `File::open(store_dir).sync_all()` after the rename; an unsupported directory fsync fails closed. On Windows, `std` does not provide a guaranteed directory durability barrier: publication explicitly returns `FileSyncedDirectoryUnproven`. **No power-loss-durable ACK on Windows**, and neither variant implies that FsStore data/outboard have been synced.
- Reopen requires reacquiring the OS lease, verifying directory/file identities, reading bounded exact-length regular records, checksum, trusted root/size/profile, monotonic sequence and no gaps. The reader returns **CheckpointClaim** candidates, not authenticated `VerifiedRanges` or skip instructions.
- An interrupted temporary file is ignored. Invalid generation names, missing older generations, changed checksum, substituted paths, wrong root, profile or size HOLD. Not reading a valid generation cannot authorize skipping bytes; at worst the transfer re-fetches the file.
- Linux/Windows process tests reopen in an actual second child OS process, plus corrupt/truncate/rename/symlink/temporary-record, replay/unaligned/quota and lost-lease controls.

## Mandatory order before G2-04b and actual resume

1. Source authority supplies an *authorized immutable* BLAKE3 root + exact size + profile. An incoming QUIC peer may NOT choose the checkpoint identity.
2. Verify incoming Bao range with trusted root; only aligned whole storage groups can be candidates.
3. While the owning process holds a validated OS lease, import verified Bao through existing pinned Iroh FsStore (G2-02), and **establish physical FsStore data/outboard/bitfield/barriers**, including relevant redb and directory semantics. The G2-02 stage API currently acknowledges only actor acceptance, **not** durability.
4. Only after those barriers write and publish immutable metadata. A committed claim is still never itself authenticated content.
5. After restart, re-acquire ownership; read metadata candidates; independently revalidate the *actual* persisted data and sparse outboard against trusted full root. Pass only proven ranges to the missing-range planner.

G2-04a implements (4) metadata only and fail-closed parsing in (5); (1), (2), (3), verified recovery in (5) remain separate integration gates. No File Gate or Akula vault rights.

## Deliberate limitations and HOLD

- Existing cooperative custody guard is NOT resistant to uncooperative writers, hardlink or path races; `validate_fence()` alone is not an atomic snapshot or safe openat2 / Windows HANDLE-relative filesystem adapter.
- The record checksum is unkeyed. An attacker able to replace files can recompute it. Even a valid record has **zero** permission to skip bytes without Bao physical revalidation.
- Windows directory sync is explicitly **unproven**. `FileSyncedDirectoryUnproven` may be useful as an observation but is not a durable ACK.
- Power-failure semantics of all filesystems, controller caches, directory entry replacement, FsStore multiple files and redb transactions are still unproven. `sync_all` of the metadata file does **not** flush other FsStore files.
- Journal generation count cap 128 provides a temporary bound, not a long-lived compaction/retirement protocol. Orphan temporary names can accumulate until G2-05 cleanup quotas. An uncooperative peer can exhaust disk outside this module.
- Cross-process `TerminateProcess` / `SIGKILL` tests of real Bao data under partial writes, and platform durable barriers, are G2-04b/G2-05.
- Reader does **not** return `VerifiedRanges`; no scheduler or production adapter can interpret a record as permission to resume.

## Evidence and acceptance for this PR only

1. Both Linux and Windows run checkpoint tests, actual second-process reopen and existing OS single-writer suite.
2. Both use a real committed identical `custody/Cargo.lock` and `cargo --locked`; no implicit dependency re-resolution.
3. Rustfmt/Clippy with no ignored errors; base Staya Rust 1.85 contracts unchanged.
4. Tests fail if metadata is torn/corrupted, wrong identity/profile, missing generation, replaced lock or symlink; interrupted temp does not count as committed.
5. PR remains Draft until exact-HEAD CI. Do NOT mark G2-04 whole task completed or enable Akula File Gate on this result.

Next: G2-04b real FsStore storage barriers, physical readback and durable actor integration. Then G2-05 killpoint and quota matrix on Windows/Linux, G2-06 independent final acceptance.


## STY-G2-05b additional checkpoint orphan quotas (isolated lab)

Prior G2-04a left `.staya-cp-tmp-*` interruption files unbounded: they were ignored (correct for trust) but unlimited in number, size and directory scanning. STY-G2-05b adds fail-closed bounds: up to 32 pending records each at most the fixed 108-byte record length, and at most 512 top-level private root entries scanned per call. Unexpected symlink/reparse or directory types under the reserved temp prefix fail closed. The reader still ignores legitimate torn temp *for content trust only*, but refuses to publish new checkpoint claims when temporary files exhaust these quotas. A separate, explicit `cleanup_pending_records` is available solely with the cooperative OS `StoreLease` held and the checkpoint writer **quiescent**. The routine checks all pending records before deleting any; on Unix it syncs the directory after unlinking. It never deletes user files, published checkpoint generations or FsStore `data` contents. No automatic deletion is triggered by read or publication. The cleanup is **not** safe against a malicious simultaneous rename/link-swap by a process ignoring locks; stronger descriptor-relative custody and Windows directory durability remain unsolved. Limits do not yet apply to actual FsStore object bytes or other process resources; G2-05 cannot be closed from this sub-gate.
