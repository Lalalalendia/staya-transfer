# ADR-0010 — STY-G2-04b: quiescent partial FsStore barrier, lab only

Parent: [STY-G2 issue #7](https://github.com/Lalalalendia/staya-transfer/issues/7), [STY-MASTER-PLAN-02](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd), merged [G2-04a PR #11](https://github.com/Lalalalendia/staya-transfer/pull/11). This carries forward *only* the unique physical file-barrier technique from superseded alternative [PR #12](https://github.com/Lalalalendia/staya-transfer/pull/12); it does NOT introduce a second checkpoint format.

## New experimental boundary

`custody::partial_barrier::publish_after_quiescent_audit` requires the existing cooperative G2-03 `StoreLease` and the canonical G2-04a 108-byte `CheckpointClaim`. The caller MUST have already stopped the pinned FsStore writer, authenticated the incoming Bao range against the local root, and imposed disk quotas.

On Unix only, using exactly the hash of the claim, it opens the existing external `.data`, `.obao4`, `.sizes4` and `.bitfield` as bounded private paths, checks regular files, same-file identities, minimal physical sizes and symlink traversal, holds all file handles, calls `sync_all` for each, and syncs the `data/` directory. It then invokes a **required caller-supplied physical audit callback**, compares backing file identities and lease after the audit, and publishes the G2-04a immutable checkpoint candidate with its separate metadata+directory barrier. No marker overwrite or parallel writer is permitted.

The callback is **not itself proof**. Tests in this PR use disposable dummy data and must not be called real Bao cryptographic verification. A future adapter using actual pinned `bao_tree::valid_ranges` and trusted full root is required to prove that the callback did the right work. Every reopened checkpoint is a **candidate** until that independent physical verification has succeeded again.

On Windows, the operation returns `Unsupported` before publication; there is no portable verified directory fsync contract with these current APIs. This fail-closed difference must be preserved until a separately tested durable Windows implementation exists.

## Tests and missing work

Linux tests cover all four file paths, both directory barriers, audit callback failure, missing sizes file, inode swap during audit, and a metadata record that is still present after data corruption but cannot by itself authorize reuse. Windows tests verify the unsupported refusal and unchanged store. Both reuse pinned `custody/Cargo.lock --locked` and existing OS file-lock tests.

These tests **do not** establish that an *active* FsStore actor has quiesced, that redb transactions and all outboard encodings are fully synced, that a second process can restore physical Bao after SIGKILL, or that a callback cannot lie. Concurrent attackers can still race pathname checks and modify the same open inode. This is **not a production writer** and **not a durable APPLIED receipt**.

Next requirements (before G2 complete): connect this module to actual G2-02 pinned FsStore `import_bao_bytes` in the interop harness, with independent `valid_ranges` audit after clean shutdown and fresh reopen; then implement crash-injection with SIGKILL/TerminateProcess, Windows durable directory protocol, quotas, external hostile-writer controls, and main-thread File Gate authorisation in STY-G3.

Merge only after exact-HEAD Linux+Windows CI. No Akula user-file modifications.
