# ADR-0019 — STY-G2-05h3a: process-owned real FsStore and OS lifecycle supervision (lab)

Parent: [STY-G2-05h #21](https://github.com/Lalalalendia/staya-transfer/issues/21) and [G2-06 #23](https://github.com/Lalalalendia/staya-transfer/issues/23). This work is stacked on G2-05h2 [PR #24](https://github.com/Lalalalendia/staya-transfer/pull/24), which itself depends on merged G2-05h1. Keep Draft until all exact-head CI passes.

## Why separate the writer into its own OS process

G2-05h2 deliberately retains the locking file descriptor until process exit when upstream FsStore loading or shutdown was cancelled. That is a valid laboratory fail-closed response, but a long-lived daemon cannot leak descriptors indefinitely. Unconditional OS unlock is also unsafe while a legitimate inherited writer may still be active.

The G2-05h3a experiment starts the REAL pinned FsStore and acquires StoreLease **only inside a dedicated worker AFTER exec**. The parent owns the OS Child handle and pipe, never the locked store FD. This removes the parent-to-worker inheritance path and makes abnormal actor cancellation recoverable by killing and reaping the entire worker process. This is a test-level prototype, not deployable IPC.

## Protocol and falsification

1. The parent creates a fresh private store root and spawns itself as a CI subprocess. The parent has no store lock. Only the child opens FsStore and takes the lease.
2. The child imports genuinely authenticated partial Bao under an InflightPermit, drops the permit, prints a READY marker and remains alive, awaiting a CLOSE command. READY is NOT a durable byte-range receipt.
3. The parent receives READY with a bounded wait and checks that a competing StoreLease attempt returns WouldBlock.
4. Clean path: parent sends CLOSE; the child irreversibly closes admission, confirms permits are drained, invokes real FsStore::shutdown, audits physical .data/.obao4 against the trusted BLAKE3 root and closes custody without forced LOCK_UN. Parent joins the worker, reacquires its own lease, independently revalidates Bao and finds no candidate checkpoint.
5. Forced-kill path: parent deliberately sends no CLOSE, kills the active worker (SIGKILL/TerminateProcess), reaps the process, reacquires custody and verifies there is no checkpoint. Whatever partial bytes remain are untrusted until independent revalidation; no previously reported READY can authorize a skipped GET.
6. A scoped process guard kills and reaps a worker during test unwinding. Startup and process-exit observation have explicit deadlines.

## Explicit limits

- Test process is a dedicated OS worker, so killing it also terminates its Tokio actor threads. This does NOT establish a general security sandbox or isolation from a malicious independent writer.
- A process join proves termination, not fsync, directory power-loss durability or journal correctness. Physical Bao audit and independent G2-06 tests are still required.
- The spawned test executable is NOT a production worker or authenticated, versioned IPC. No parent-death watchdog or executable identity verification yet.
- It runs in pinned Iroh release/fork CI on Linux. A separate real Windows child-owner fixture is needed before claiming cross-platform production isolation.
- No Akula File Gate, verified durable resume, G2-06 sign-off or permission integration follows from this test.

Next G2-05h3b: dedicated writer binary, authenticated local IPC, parent-death detection, bounded supervisor cancel/terminate/join semantics and two-platform tests. Do not merge h3a before the h2 dependency is accepted and its own CI is green.
