# STY-G2-05h3g3: first-party Windows credentialed IPC ARM laboratory

Parent: supervisor issue #26. Accepted prerequisites: Windows JobObject #46, pinned real FsStore #49, Linux kernel IPC #56. Linux FsStore IPC connection #59 is separately in Draft at authoring time.

## Lifecycle

- Launcher creates a unique BCryptGenRandom-backed pipe name before launching its worker. Named pipe enforces FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_REJECT_REMOTE_CLIENTS, noninheritable handle and explicit owner-account/LocalSystem-only SID DACL (not Windows default Everyone/Anonymous read access).
- Worker starts CREATE_SUSPENDED, is assigned to KILL_ON_JOB_CLOSE Job Object before ResumeThread. Only then does it open the private pipe with SECURITY_IDENTIFICATION.
- Worker verifies GetNamedPipeServerProcessId against expected launcher PID and opens a kernel process handle. Launcher checks GetNamedPipeClientProcessId against exact assigned Job worker PID and retains a process-only wait handle.
- Only after mutual kernel PID checks does parent send fixed STYW/v1 40-byte ARM frame with cryptographically random 32-byte nonce; worker verifies and sends exact ACK. No fixture marker is written until this completes.
- Real Windows tests prove positive ARM, wrong claimed server PID denial, wrong actual worker PID denial, missing pipe denial, and actual independent launcher TerminateProcess killing Job-bound authenticated worker. Stable and Rust 1.91 Windows CI retains strict fmt/Clippy.

## Deliberate HOLD boundary

Separate Windows native lab only, NOT connected to real pinned FsStore, Akula or File Gate. Same-user interference/DoS is still possible; compromised launcher controls endpoint and nonce; neither executable code-signing nor device entitlement is established. This uses blocking synchronous named-pipe IO: there is no bounded production cancellation, CancelIoEx, overlapped server or graceful actor shutdown. The JobObject is native containment, not an independently protected authorization root. No Quiescent, Released, verified resume, signed GRANT, ALLOW, APPLIED or ACK. Supervisor #26, G2-06 #23 and File Gate remain HOLD.

Microsoft Win32 API references: CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId and Named Pipe Security and Access Rights.