# ADR-0012 — STY-G2-05d: ownership identity descriptor lifetime and reacquisition

Parent: [STY-G2 issue #7](https://github.com/Lalalalendia/staya-transfer/issues/7) and [STY-MASTER-PLAN-02](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd). The scope is **one existing cooperative OS lock**, not implementing new locks, FsStore data recovery, or Akula sync.

## Observed, not yet proven cause

On [G2-05b PR #15 CI #39310589926](https://github.com/Lalalalendia/staya-transfer/actions/runs/39310589926), the first Linux run of pre-existing `malformed_filename_and_missing_generation_fail_closed` failed when `StoreLease::acquire` returned `WouldBlock` immediately after an earlier `StoreLease` was dropped. The Windows run passed, and a retry of the Linux job passed on unchanged source. This is **flakiness**, not a reproducibly identified root cause.

The prior lease constructor retained `same_file::Handle::from_file(file.try_clone()?)` in the lease, where `file` is the descriptor holding the OS lock. Per Rust `File::try_lock` documentation, the lock stays active while any duplicated/inherited locking description remains open. Retaining an extra clone throughout custody unnecessarily lengthens the set of handles that must close. It may contribute to a lock-lifetime race, but the single observed failure does not prove that causal link.

Reference: https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock

## Minimal implementation change

- Open and hold one `File` as the actual OS lock authority, without any explicit `unlock()` in `Drop`. This avoids prematurely unlocking a lock that might still protect an inherited child descriptor.
- Temporarily create a short-lived `Handle::from_file(file.try_clone()?)` only to compare the identity of the opened locking file against a **separately opened path identity Handle::from_path(lock_path)**. If the file changed between operations, HOLD. Drop the clone **before** attempting `File::try_lock`; retain the independent path identity handle only for later comparisons in `validate_fence()`.
- Preserve symlink/reparse, owner identity, path-swap and hardlink tests from G2-03.
- New deterministic test without retries: 128 sequential acquire/validate/drop cycles, including 4 independent child-process BUSY checks while owner holds the lock and 4 independent ACQUIRED checks immediately after release, on both Linux and Windows.

## Acceptance and limits

- Exact-head Windows/Linux fmt, test, Clippy PASS with committed `custody/Cargo.lock --locked`. No dep changes.
- Run a second independent acceptance attempt if feasible to detect transient flakiness; a CI retry alone does **not** prove zero leak probability.
- If old `WouldBlock` recurs after this patch, diagnose physical inode identity, descriptors and process ownership rather than silently retrying `StoreLease::acquire`. This patch makes resource lifetime smaller and checkable, but we must not declare a confirmed root cause without repeatable evidence.
- POSIX `flock` and Windows `LockFileEx` are cooperative; hostile writes or concurrent pathname replacement remain possible. Linux fork-inherited lock descriptors, Windows ReFS identity false-positives, and Windows directory durability remain outside scope.
- All G2-05 post-SIGKILL physical Bao guarantees remain governed by separate G2-05a. This PR cannot mint verified ranges, publication rights or Akula File Gate authority.

## Parallel-suite falsification and deterministic inheritance probe (20 October 2026)

At exact-head GitHub Actions #39316625306, Linux ran eight serial full integration-test suites with **0 failures**, versus eight parallel full suites with **7 failures**; isolated untraced Drop-only stress had **0/16 failures**. Windows passed. Linux failure is `File::try_lock: WouldBlock` on a freshly reopened lockfile, and an inspection **after** failure found no matching fd or /proc/locks entry. Thus the strongest observation is a parallel test/process timing dependency, not an established kernel bug.

Hypothesis: a concurrently spawned child briefly inherits a `flock`-carrying open file *description* before `exec` closes its inherited descriptor. When the original owner closes during that window, the kernel lock may outlive it. This is not yet a verified explanation for the CI failure.

The Linux-only `inherited_lock_description_survives_parent_close_until_child_exit` regression deliberately passes a duplicate of a locked file description as child stdin, waits for the child to confirm startup, closes the parent's original FD, verifies a separate process gets BUSY, kills/reaps child, then verifies ACQUIRED. It tests Linux descriptor-lifetime semantics **without** depending on the spontaneous scheduling race. The mandatory original parallel stress remains unchanged. Neither test warrants explicit `unlock()` in `Drop` or production deployment.

Before any root-cause claim: inspect exact-head CI, then distinguish the artificial inherited-FD proof from the real non-inheriting subprocess path. Consider whether Rust stdlib's spawn closes descriptors at exec and whether lock lifetime could be extended only in a pre-exec interval. Preserve normal fail-closed behavior and isolate production ownership from test-only mitigations.

## Premature unlock counterexample (new test; CI pending)

The Linux-only `explicit_unlock_while_child_inherits_descriptor_allows_premature_second_owner` test passes an actual duplicate of a held `flock` open-file-description into an independently running child. While that child is confirmed alive and still has the descriptor, the parent issues explicit `File::unlock()`; a third cooperative process is then expected to acquire the exact same inode. This falsifies the unsafe assumption that an explicit unlock is harmless just because the parent's scope has ended. **The test proves lock semantics only**, not that the child was still performing FsStore writes. It must pass exact-head Linux CI before being counted as evidence.

No production `Drop` or Akula File Gate is changed. A future quiescence contract must prove all owned writers/actors stopped before explicit release, not merely that the parent file descriptor was dropped. Keep PR #17 blocked until the inherited-child negative test, original Drop stress and cross-platform gates can coexist.
