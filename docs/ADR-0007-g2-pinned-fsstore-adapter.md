# ADR-0007 — STY-G2-02: verified Bao import to pinned FsStore (clean reopen, NOT crash-safe)

**State:** implementation under test in a separate G2-02 draft PR. Canonical task: [STY-G2 #7](https://github.com/Lalalalendia/staya-transfer/issues/7). Continues merged [G2-01](https://github.com/Lalalalendia/staya-transfer/pull/8). No change to Akula, no user files, no storage rewrite.

## Pinned APIs inspected

- `iroh-blobs@a8f5b65d3e4ae0be7d9be7907458b9f1fd56aefa`, `src/api/blobs.rs`: `Blobs::import_bao_bytes(hash, ChunkRanges, data)` validates Bao via upstream `ResponseDecoder` before sending already verified items to FsStore. The `ImportBao` actor **assumes its input items are already verified**, so never feed it peer-produced `BaoContentItem` directly.
- `src/store/fs.rs`: `FsStore::load`, `Store::shutdown` and `Blobs::observe` are stable public entrypoints for this fixture. The source explicitly warns that partial writes are not guaranteed to persist after abrupt process loss. Clean shutdown is not SIGKILL durability.
- `src/store/fs/bao_file.rs`: partial files `.data`, `.obao4`, `.sizes4`, `.bitfield` and `PartialFileStorage::sync_all`. Data/outboard/sizes are flushed; the bitfield is written afterwards. This does not establish directory durability, process fencing or a transaction spanning all files.
- `src/store/fs/options.rs`: large partial entries are on disk; small complete files/outboards may be inlined into redb. Future physical audit must handle BOTH representations; this test intentionally uses one large partial object.
- `src/api/remote.rs`: `local_for_request` and `LocalInfo::missing` consult the stored bitfield. This is a *candidate range map*, not proof of post-crash physical persistence. Akula must not skip based on it alone.

## Implemented G2-02 laboratory boundary

`interop/fsstore_partial_adapter.rs` exposes a **test-only** staging function taking a trusted `StoreIdentity` (BLAKE3 root, exact length, Bao profile), an aligned-by-codec range and bounded wire Bao. It refuses wrong profile/header/root, malformed/trailing proof before ANY store mutation, then uses the pinned upstream `Blobs::import_bao_bytes` rather than authoring a new storage database. Return type is deliberately `AcceptedIntoUncommittedFsStore`, never a durable receipt.

`interop/fsstore_partial_gate.rs` uses real pinned release/fork FsStore with a deterministic 8 MiB + 17-byte blob, imports a partial Bao range, CLEANLY shuts down and reopens the store, and separately authenticates physical `.data` + `.obao4` using Bao proofs and Staya `verify_bao_range`. Negative controls: changed root, size, profile, proof, missing proof, modified physical bytes. Run in both fork and release independent locked CI.

**Boundary:** `audit_clean_closed_fixture` opens pathname-based test files without OS-level custody checks and assumes disposable private dirs and no concurrent attacker. It must not be used as a production audit. No production lifecycle code has been exported or wired into Akula. `--locked` still uses existing Git-generated Cargo.lock; no re-resolution or new dependencies.

## Remaining G2 gates

- G2-03: OS-exclusive single writer, path/fd identity, symlink/hardlink races, multi-process Windows/Linux.
- G2-04: durable content/outboard/journal barriers and atomic checkpoint; startup recovery revalidates physical bytes, redb inline, outboard/sizes4 and file identity before admitting skip ranges.
- G2-05: SIGKILL/TerminateProcess timing injection, safe full redownload if bytes lost, admission quotas/cancellation/resource controls.
- G2-06: exact SHA CI and two-host/fork coverage; no claims of production durability or Akula File Gate before this gate.

**Acceptance for this PR only:** release/fork `--locked` both run the actual test, source Rustfmt/Clippy pass, prior G1e tests still pass. Do not merge while CI fails, and do not claim crash-resume on clean-shutdown evidence.