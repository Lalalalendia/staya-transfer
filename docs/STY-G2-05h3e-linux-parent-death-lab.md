# STY-G2-05h3e - Linux native parent-death/pidfd experiment

**Draft, LAB only.** Parent [supervisor issue #26](https://github.com/Lalalalendia/staya-transfer/issues/26), [G2-06 release HOLD #23](https://github.com/Lalalalendia/staya-transfer/issues/23). Independent dependency-free Rust crate native-host; no Akula or end-user files.

## Implemented
- A narrow Linux native syscall module with unsafe confined to native-host/src/linux.rs. It uses CommandExt::pre_exec to register PR_SET_PDEATHSIG=SIGKILL before exec and checks the expected parent PID. A separate pidfd_open provides a stable kernel process-exit witness; the child double-checks parent liveness before reading private ARM.
- Three independent process tests: grandparent -> launcher -> worker, with the launcher terminated by real SIGKILL after the child is armed, with the child unarmed, and wrong-parent identity rejected before ARM. The grandparent pins a real child pidfd before killing the launcher; it must see kernel exit even when child was blocked on private stdin.
- Test readiness files use the original writable handle plus write, sync_all, close and rename. Readiness is only a test sequencing signal; pidfd, not a marker or textual PID, is the exit witness.
- Linux CI runs real OS-process tests, locked no-dependency Cargo manifest, fmt, Clippy deny warnings and Rust 1.91 compatibility. No existing production crate or GitHub workflow is weakened.

## Security boundary
This is NOT a production parent-death guarantee. A child-side getppid plus pidfd_open of a claimed PID after fork/exec does not cryptographically or conclusively bind the original creator against all PID-reuse/startup races. PDEATHSIG follows Linux parent-thread semantics. The parent should issue a stable pre-spawn pidfd through protected OS IPC before trusting this for arbitrary executables. Linux pidfd_open number 434 is covered on x86_64 and aarch64; missing kernel/architecture support means HOLD.

No Windows Job Object, no real pinned FsStore/StoreLease actor, no authenticated/versioned IPC, no Bao, no hardened pathname authority, no cancellation-safe actor opening, and no File Gate. The safe custody/src/lib.rs remains forbid(unsafe_code).

## Next critical dependencies
1. Make parent identity non-forgeable across every spawn/death window by handoff of a supervisor-originated pidfd and full parent-liveness watch, including fault injection before exec and after ARM.
2. Windows: CreateProcessW suspended, configure noninheritable KILL_ON_JOB_CLOSE Job Object, assign the suspended child, only then ResumeThread. Any nested-job or assignment error => child hard terminate and deny ARM.
3. Move pinned FsStore actor and original StoreLease into the contained worker process. Require protected IPC, bounded cancellation/join, independent Bao proof and actual OS parent/child exit before clean release. Leave #26 OPEN, G2-06 and Akula File Gate HOLD.
