# ADR-0008 — STY-G2-03: cooperative exclusive OS owner (experimental)

Parent: [STY-MASTER-PLAN-02](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd) and [STY-G2 issue #7](https://github.com/Lalalalendia/staya-transfer/issues/7). G2-01 is in main. G2-02's pinned FsStore Bao adapter is reviewed separately in PR #9. This PR does **not** alter that branch, Akula, a user's vault, or the network stack.

## Actual deliverable

A standalone `custody/` crate with Rust >=1.91 and a separate lockfile, not a new blob store or a change to Staya's Rust 1.85 core. A non-cloneable `StoreLease`:

1. Requires an existing, locally selected private store directory (no remote path input).
2. Rejects lexical parent traversals, symlinks at all walked path components, Windows reparse points, non-directory roots and nonregular custody files.
3. Opens `.staya-writer.lock` without truncation and takes an **OS file lock** with `std::fs::File::try_lock`. Never deletes a stale-looking file or trusts a PID in it.
4. Retains the lock FD/Windows HANDLE for the session, plus separately opened physical identity handles for directory and lockfile via pinned `same-file 1.0.6`.
5. Exposes `validate_fence()` which rechecks directory and lockfile identity before a writer operation; moved/replaced paths HOLD. Only the lease holder should be able to invoke a future FsStore writing adapter.

## Independent Windows and Linux tests

- Parent process owns a store; separate child process cannot acquire it.
- Independent worker holds the lock; parent verifies the second process is denied. Kill the holder with Linux SIGKILL or Windows TerminateProcess, reap it, and verify a third independent process can acquire. This proves **lock release**, not durability of data that the killed process was writing.
- A stale lockfile does not block a new process after the former lock handle has closed.
- Equivalent root spellings and a hardlink to the locked inode do not bypass the OS lock.
- Swapping the lockfile or directory identity after acquisition is rejected by `validate_fence` whenever the OS permits that replacement. On Windows, disallowed replacement is itself an observed OS protection; it does not prove a third-party process cannot replace other paths.
- POSIX symlink alias rejected; a Windows directory symlink is rejected if the runner permits creation. Windows reparse-point rejection is tested through code but junction privilege coverage needs an additional authenticated setup.

## Known limits (HOLD)

- **Cooperative enforcement only:** a malicious or buggy writer that ignores the lock can mutate files. POSIX flock semantics may leave a lock held if a forked process inherits its descriptor; killing one owner is not enough unless *every* inheriting handle closes. No fork-inheritance safety proof here.
- **Path TOCTOU remains:** open-by-path after a link check is not atomic. A hostile actor can potentially swap a symlink between the check and open, and a successful `validate_fence` does not reserve the path for a future write. Before connecting this code to an FsStore writer, require pinned FD-relative opens/openat2 on supported Unix, robust Windows handle-relative/identity checks, and an explicit policy for external writers and filesystem reparse tricks.
- Windows file identity as implemented by `same-file` has documented potential false positives on some filesystems (notably ReFS). This implementation therefore is not yet an adversarial Windows storage security boundary.
- No ownership across different *actual directories* merely because their appdata strings look related. The caller must choose one stable canonical vault/store location. S3 and Akula custody must be integrated separately.
- No durable checkpoint, fsync, atomic rename, readback, partial Bao persistence after SIGKILL, crash injection of FsStore data, Windows disk-durability guarantee, File Gate, permission grant, or production sync.
- `std::fs::File::try_lock` stabilized in Rust 1.89; the root Staya library remains Rust 1.85 by isolating this experimental crate.

## Merge gates

1. Both Linux and Windows workflows pass on **exact PR HEAD** with fmt/test/clippy.
2. Actual generated `custody/Cargo.lock` is committed and rerun with `--locked`; no floating transitive dependencies.
3. Test binary visibly proves process isolation and termination/unlock; do not accept an in-process Mutex-only test.
4. G2-02 and G2-03 are separately merged/tested before connecting the guard to any real FsStore mutation. Keep `STY-G2 durability_complete=false` and `Akula File Gate=false`.

Next: G2-04 add durable checkpoint ordering and actual physical range revalidation under one owner, with all race exclusions above explicit until independently fixed.
