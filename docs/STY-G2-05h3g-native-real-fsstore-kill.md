# STY-G2-05h3g — real pinned FsStore under Linux and Windows native containment (lab)

Parent: [supervisor #26](https://github.com/Lalalalendia/staya-transfer/issues/26). Earlier accepted prerequisites: Linux PDEATHSIG/pidfd [#44](https://github.com/Lalalalendia/staya-transfer/pull/44), suspended Windows JobObject [#46](https://github.com/Lalalalendia/staya-transfer/pull/46), actual pinned actor + lock ownership [#41](https://github.com/Lalalalendia/staya-transfer/pull/41).

## Single actual writer process

A **new binary** in the pinned release/fork interop crates starts **the real** \`iroh-blobs::FsStore\` after \`StoreLease::acquire\` in its own OS process. It writes a deterministic real object through \`FsStore::add_slice\`, validates the root, then retains the actor, tag and lock until the OS destroys the process. Unexpected worker errors/panics abort the entire OS process; they must not accidentally drop custody while an actor runs. No parent-held lock FD is transferred into the worker.

- **Linux:** the separate launcher installs \`PR_SET_PDEATHSIG=SIGKILL\` before exec; the worker checks the actual parent through \`bind_actual_parent\`/pidfd **before** store acquisition. A third process holds a pidfd exit witness.
- **Windows:** the launcher uses the existing \`SuspendedJobWorker -> AssignedJobWorker -> RunningJobWorker\` API. \`CREATE_SUSPENDED\` and assignment to a **noninheritable** \`KILL_ON_JOB_CLOSE\` Job Object precede \`ResumeThread\`. A third process holds a process-only wait handle, not a Job handle.
- Both: after a true launcher hard-kill, the observer requires **native OS worker exit**, independently reacquires the store lock, audits real \`.data\`/\`.obao4\` bytes against a trusted BLAKE3 root, and verifies no checkpoint candidates. The root is a unique disposable CI fixture.

## Evidence gate

The new integration test is included in **both** Linux pinned release/fork Iroh compatibility and Windows release/fork FsStore workflows. Strict \`cargo fmt --check\`, \`cargo clippy -D warnings\` and \`--locked\` continue to apply. The two interop lockfiles explicitly include the native local path dependencies and must not drift.

## Deliberate omissions / HOLD

**This is a native crash experiment, NOT a production supervisor.** The binary has no clean CLOSE, no authenticated/versioned IPC, no production command handling or root provisioning, no privileged executable identity check, no real mid-load cancellation injection and no bounded graceful actor shutdown. Root path/parent PID are lab-controlled inputs. Linux's child-opened pidfd is not an inherited, supervisor-minted identity capability; Windows's binary does not prove its own job membership. A malicious independently launched process is outside this proof. The post-kill Bao audit is a physical integrity test, **not** a disk power-loss durability guarantee or durable missing-range skip authority. A full actor write completes before the forced kill; cut-points inside load/shutdown remain untested here.

**Never mint** Quiescent, Released, verified checkpoint, resumable-skip, ALLOW, APPLIED, or Akula File Gate authority from this test. Keep #26 and G2-06 #23 OPEN/HOLD.

Next: authenticated bounded local IPC and OS-credential/executable binding; fail-closed daemon-side command gate, Windows assignment failure under real nesting, deterministic load/shutdown cancellation, bounded explicit close/abort/reap, and independent Bao proof after each forced termination.
