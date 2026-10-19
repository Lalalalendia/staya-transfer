# ADR-0013 — STY-G2-05e: actual Windows FsStore TerminateProcess/reopen gate

Status: **Draft, CI unverified** (20 October 2026). Parent: [STY-G2 issue #7](https://github.com/Lalalalendia/staya-transfer/issues/7), [STY-MASTER-PLAN-02](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd). Independent of blocked [G2-05d #17](https://github.com/Lalalalendia/staya-transfer/pull/17).

## The missing evidence

[G2-05a #14](https://github.com/Lalalalendia/staya-transfer/pull/14) added real pinned FsStore two-process kill/reopen tests and passed on Linux for both `iroh-blobs 0.103.1` and the pinned fork. Those were **not** Windows FsStore tests. G2-03 Windows OS file-lock tests cannot substitute for killing a live **FsStore** actor and independently reopening physical Bao data.

## Test protocol and invariants

A standalone Windows Actions matrix executes `interop/fsstore_crash_gate.rs` unchanged for the same two immutable dependency variants with their already committed `Cargo.lock` and `--locked`.

- In **uncommitted** mode, a child process creates a real pinned `FsStore`, imports authenticated partial Bao under an OS lease, reports READY **without** clean store shutdown or checkpoint, and the parent calls `Child::kill` (Windows: `TerminateProcess`). Parent waits for termination, reacquires the private store, confirms zero committed checkpoint candidates, independently audits any surviving data and Bao, and reopens the real pinned backend. Physical bytes may survive or be lost; neither state grants `trusted_skip`.
- In **checkpointed-attempt** mode the child cleanly shuts down the actor, but the Windows partial durability barrier must report `Unsupported` and no checkpoint may be published. Parent kills this now-idle child, then independently verifies **zero checkpoint candidates** after reopening. It does not claim this data is durably committed.
- A log marker `STY_G2_05E_WINDOWS_TERMINATE_PROCESS` confirms actual non-graceful child exit in each scenario; a second marker is only printed after both cases pass. Tests must reject a graceful exit, unbounded wait, wrong root, and any unauthorized inference from backend bitfields.
- No real user files, installed Akula, or remote transport. Work happens in test-created private temporary directories; the Rust library's `File Gate` is not invoked.
- The CI job additionally requires `cargo metadata --locked`, Windows Clippy and rustfmt. Two independent jobs (upstream release/fork) must pass at the **same exact PR HEAD** before merging.

## Not established

- Power-loss durability, directory rename/fsync barriers on Windows, ReFS/hardlink/junction adversarial identity, an untrusted second writer ignoring advisory locks, durable verified skip/resume after TerminateProcess, `fsstore` partial state retained after a crash, or any Akula Vault ACL/commit.
- Full crash-injection coverage at each data/outboard/bitfield/journal/fsync boundary. This additional matrix is necessary but not sufficient for G2-06.
- The Linux reacquisition `WouldBlock` issue under [PR #17](https://github.com/Lalalalendia/staya-transfer/pull/17) remains blocked. A green Windows run is not a reason to bypass that gate.

## Acceptance checklist

1. Both `windows-latest` jobs compile and run native `fsstore_crash_gate` under committed lockfiles, no dependency update.
2. Logs include both `STY_G2_05E_WINDOWS_TERMINATE_PROCESS mode=uncommitted` and `mode=checkpointed`, plus final `...PASS` marker.
3. All negative checks, fmt, Clippy succeed. Record exact head SHA and run URLs in master plan.
4. Only then consider merging as a **limited lab verification**; G2 durable checkpoint and File Gate remain HOLD.
