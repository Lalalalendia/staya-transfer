# STY-G2-05h3g1: Linux inherited-socket credentialed ARM laboratory

Parent: [production supervisor #26](https://github.com/Lalalalendia/staya-transfer/issues/26); Linux parent-death lab [#44](https://github.com/Lalalalendia/staya-transfer/pull/44); real pinned FsStore parent-death integration [#49](https://github.com/Lalalalendia/staya-transfer/pull/49), still independently awaiting final acceptance at authoring time.

## What is implemented

Linux-only native-host code creates an **anonymous Unix socketpair** in the same trusted launcher that will spawn the child. The child end is transferred through an async-signal-safe dup2 to fixed descriptor 3 in the pre-exec interval; no public pathname socket or network listener exists. The launcher installs PR_SET_PDEATHSIG=SIGKILL and checks the actual parent before exec. After exec, the child must check getppid/pidfd and the kernel's SO_PEERCRED on the inherited descriptor: original creator PID, UID and GID must all match before reading any protocol content.

One bounded 40-byte versioned STYI/v1/ARM record carries an OS-random 32-byte nonce. The worker responds on **the same exclusive inherited FD** with STYI/v1/ACK and the same nonce. Non-zero reserved fields, unknown command/version, zero nonce, replay/mismatch, missing FD, short read, wrong parent and timeout all reject the request, before any test file write. Typestate makes the launcher move from UnarmedWorker to ArmedWorker only after the verified reply. On error, the lab guard terminates and reaps its OS child; accidental Drop is not a clean closure.

Real OS tests verify no pre-ARM writes, correct PID/UID/GID and nonce exchange, wrong parent denial, missing socket refusal and SIGKILL of launcher followed by pidfd proof of worker death. The original Linux parent-death tests remain enabled. No third-party dependencies were added; Rust 1.91, rustfmt, strict Clippy and actual OS tests run in the existing native Linux workflow.

## Exact limits and next work

This is a first-party Linux **IPC bootstrap**, NOT a production supervisor nor a security boundary against malicious code injected into the trusted launcher. There is no executable identity measurement, privileged launcher separation, Windows equivalent, clean CLOSE, credentialed command protocol for writes, real FsStore connection, bounded production abort/join or Akula File Gate. SO_PEERCRED captures credentials at socket creation; it is combined with live getppid/pidfd rather than treated as proof of non-rollbackable permission. PID strings alone are not accepted as authority.

Next: connect this inherited IPC admission to the actual process-owned FsStore after #49 lands, implement authenticated + bounded versioned commands and Windows verified named-pipe / explicit handle binding, then injection tests during FsStore startup/shutdown. Do not issue Quiescent, VerifiedResume, ALLOW, APPLIED or File Gate.
