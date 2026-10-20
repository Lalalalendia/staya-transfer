# ADR-0024 — G2-05h3b: orphaned FsStore writer after parent hard kill

Status: **research / DRAFT / fail closed**. Parent: [STY-G2 #7](https://github.com/Lalalalendia/staya-transfer/issues/7); production supervisor acceptance: [#26](https://github.com/Lalalalendia/staya-transfer/issues/26); independent release gate: [#23](https://github.com/Lalalalendia/staya-transfer/issues/23). Follows the accepted laboratory subprocess [#27](https://github.com/Lalalalendia/staya-transfer/pull/27).

## Concrete OS-process experiment

The grandparent test starts a **launcher OS process**. The launcher starts a **separate writer OS process** via an anonymous, one-way stdin pipe and retains the only writer endpoint. The writer alone opens a real pinned Iroh FsStore (both pinned release and fork CI variants) with a real exclusive StoreLease, imports one authenticated Bao range, drops its in-flight admission permit and publishes a disposable *test-only readiness marker*. No checkpoint is published.

After a real one-byte ARM command and child-side acknowledgement prove that the private pipe is connected and writer is alive, a competing StoreLease acquisition must return exactly WouldBlock. This observation is required, not inferred from a stale ready file. The grandparent then hard-kills the **launcher**, not the writer, with the native OS process kill primitive (SIGKILL on Linux; TerminateProcess on Windows). The writer must observe EOF from its private control channel, record a diagnostic marker and force its **own OS process exit** without producing clean shutdown, candidate checkpoint, skip token, durable ACK or application receipt. A fresh independent process must obtain real OS custody and find **zero** checkpoint candidates.

A bounded retry of observing fresh OS acquisition **in the test only** accounts for process teardown; it is not a production retry of failed ownership admission. All test roots are created under private disposable temporary directories; no Akula files are used.

## Why EOF must never become quiescence

The parent may have died in the middle of an FsStore actor operation. Pipe EOF cannot attest successful actor shutdown, flushed backing files, directory fsync, completed child-writer registry, physical Bao continuity or stable writer identity. The orphan therefore terminates without a clean-ACK or a candidate checkpoint. An independent post-crash owner must still revalidate data/outboard before any retained-byte skip.

The launcher never acquires or passes an OS lock FD; the child opens its own lock after exec. This avoids making the launcher the lock owner and prevents the particular inherited-parent-FD ownership pattern described in blocked diagnostic [#17](https://github.com/Lalalalendia/staya-transfer/pull/17).

## Not established: production parent-death containment or authenticated IPC

- An anonymous stdin pipe limits direct reachability but is **not a versioned, authenticated, hostile-client-safe IPC protocol**. A leaked/inherited copy of its writer endpoint can delay EOF after parent death.
- There is no OS-enforced Linux PDEATHSIG/pidfd parent lease, Windows job-object kill-on-close, startup handshake identity attestation, protected channel, credential binding, or non-forgeable child-writer registry.
- No injected cancellation mid-real FsStore::load, mid-shutdown, disk-full error, power loss, adversarial store-path swap, or partial-write recovery.
- A self-exiting orphan is deliberate **failure containment**, not a successful clean handoff or acceptable long-lived daemon supervisor. The test must never be represented as a production implementation.
- No peer grant, VaultId, File Gate write, G2-06 completion or APPLIED receipt.

## Exact-head acceptance for this PR only

- Pinned release and pinned fork run the exact same **three-OS-process** test in the Linux Iroh interop workflow using Cargo.lock --locked.
- The test records: writer owned actual FsStore, competing custody BUSY before parent death, parent OS hard kill, child observed orphaned-channel EOF, absent clean-ACK/checkpoint and independent post-exit StoreLease success.
- Full Rustfmt, Clippy -D warnings and the existing Windows/native/custody gates must remain successful on the **same HEAD**.
- Any failed or missing test leaves this PR Draft. Do not merge to claim complete #26.

## Next substep

Build a production-owned worker process with a bounded and cancellable supervisor, **registered child-writer authority**, explicit protocol framing and authentication bound to OS process identity, OS-backed parent-death containment (Linux/Windows), actor-start cancellation and bounded abort/join. Only an authenticated owner that completed real actor shutdown plus all child joins may reach Quiescent and allow an explicit clean-release path. Until then, #17, #26 and G2-06 stay HOLD.

## Follow-up: Windows rejection in first exact-head CI

The original head `852b86bb` passed Linux pinned release/fork parent-death test, but failed rustfmt and native Windows. Windows rejected the **pre-parent-death competing owner** assertion before any kill. No unsafe assumption of exclusive custody was made: the test failed closed. The revised test adds a real parent->child ARM/ACK handshaking byte, rejects premature EOF before the grandparent probe, and prints the exact competing StoreLease result on failure. This is diagnostic and must pass fresh Linux+Windows release/fork exact-head CI before any merge. The initial branch was also based on a pre-#32 main and could conflict with accepted G2-06f tests; the replacement branch starts from main@4ad4e14 and retains G2-06f code.

## Native Windows marker publication correction (20 October 2026)

The real Windows release/fork falsifier exited before ARM because File::open() creates a read-only handle and FlushFileBuffers/sync_all returned PermissionDenied (Win32 error 5). Every test readiness marker now uses a newly created, writable, exclusive temporary file: write_all, sync_all on its original writable handle, drop the handle, and rename to the visible marker path. The parent therefore never mistakes an incompletely written marker for a readiness proof. The actual StoreLease BUSY and parent-hard-kill assertions remain unmodified. This remains a laboratory test and must pass fresh exact-head Linux and Windows CI.
