# STY-G2-05h3g2 — Linux credentialed IPC before actual FsStore custody

Parent: supervisor issue #26. Accepted predecessors: #49 (real pinned FsStore + OS parent death; merged ea6f6f9e) and #56 (Linux kernel SO_PEERCRED ARM; merged d7decc08).

## Boundary

1. The first-party Linux launcher uses a private anonymous socketpair and the accepted native-host code to install PDEATHSIG before exec, pass FD 3, authenticate SO_PEERCRED PID/UID/GID plus live pidfd, and exchange a versioned 40-byte ARM/ACK with OS-random 32-byte nonce.
2. The actual pinned release/fork staya-store-worker calls receive_parent_arm before StoreLease::acquire, FsStore::load, any actor, or any filesystem write. A rejected IPC admission exits with status 73 before acquiring custody. Once it owns the store, prior process-abort-on-error remains unchanged.
3. A three-process integration test requires no lockfile/data before ARM, then writes a full real FsStore object under its exclusive lease, kills the launcher, observes worker exit via a separate pidfd, reacquires the lock and independently Bao-verifies physical data/outboard against trusted BLAKE3; no checkpoint is published.
4. Three additional native negative tests on both pinned Linux release/fork variants cover missing ARM, wrong claimed parent, and missing inherited socket. All must leave the lockfile, FsStore data directory, and readiness marker absent. CI runs them explicitly.

## Deliberate limits

The Windows JobObject real FsStore path is unchanged; it is not evidence of Windows credentialed IPC. This is a laboratory first-party bootstrap, not signed executable attestation or privileged independent custody. Linux PID reuse/races are not absolutely eliminated, SO_PEERCRED reflects socket creation credentials, and no production commands, clean CLOSE, bounded graceful actor shutdown, mid-load/shutdown cancellation, power-cut durability, trusted resumable skip, entitlement, Akula File Gate, ALLOW or APPLIED is provided.

Keep issue #26 and G2-06 #23 OPEN/HOLD. Next: Windows credentialed channel binding, controlled command protocol, cancellable startup/shutdown with bounded abort/reap and independent Bao proof after every abnormal completion.