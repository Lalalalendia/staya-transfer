# STY-G2-05h3g5 — bounded Windows named-pipe ARM/ACK with CancelIoEx completion

Prerequisites: accepted Windows native IPC #62, accepted Linux kernel IPC + real FsStore #59; real Windows FsStore integration #66 separately under CI at implementation time.

## Threat and concrete change

Windows synchronous ConnectNamedPipe, ReadFile and WriteFile can wait indefinitely for an uncooperative peer. A simple timeout followed by CancelIoEx is **not** sufficient: cancellation is asynchronous, and returning early can free stack OVERLAPPED/event/buffers while the kernel still accesses them.

This standalone native-windows-host PR changes **both ends** of the existing STYW/v1 pipe to FILE_FLAG_OVERLAPPED. A common bounded deadline covers ConnectNamedPipe, WriteFile(ARM) and ReadFile(ACK) for the launcher and ReadFile(ARM), WriteFile(ACK) for the worker. Each request owns an exclusive manual-reset Win32 event and stack OVERLAPPED, then gets an actual GetOverlappedResult completion. On timeout, issue CancelIoEx for the precise OVERLAPPED, wait for completion, and refuse session promotion even if IO raced cancellation. If cancelled IO does not settle within a second finite grace window, abort the isolated OS process instead of freeing still kernel-owned memory. Parent JobObject close remains the last-resort kill barrier.

Real Windows OS tests include absence of any client at ConnectNamedPipe, an actual connected JobObject worker whose parent withholds ARM, plus all earlier five positive/negative PID, nonce and OS parent-kill tests. Both Windows stable and Rust 1.91, strict fmt/Clippy, and the existing pinned FsStore tests must remain green.

## Remaining HOLD

This is a lab fail-closed timeout mechanism, NOT an installed or reusable production supervisor. Abort-on-unsettled-cancellation is intentionally destructive; a production worker must isolate fault domains and explicitly coordinate actor shutdown. No signed executable identity, independent entitlement or Akula File Gate, no clean FsStore close, no forced load/shutdown cancellation, no durable checkpoint/resume/ALLOW/APPLIED. #26 and G2-06 remain HOLD.

Source API contracts: Microsoft Learn Synchronous and Overlapped Pipe I/O, ConnectNamedPipe, CancelIoEx and GetOverlappedResult.