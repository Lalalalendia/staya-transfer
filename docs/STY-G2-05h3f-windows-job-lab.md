# STY-G2-05h3f — Native Windows suspended JobObject laboratory

Status: DRAFT; native Windows OS process containment prerequisite, **not production supervisor**. Parent [supervisor #26](https://github.com/Lalalalendia/staya-transfer/issues/26) and release [G2-06 #23](https://github.com/Lalalalendia/staya-transfer/issues/23).

## Implementation

A separate zero-runtime-dependency Rust 1.91 crate `native-windows-host/` isolates all native Win32 FFI; `custody/src/lib.rs` retains its existing `#![forbid(unsafe_code)]`. `CreateJobObjectW` creates an anonymous noninheritable Job handle; `SetInformationJobObject(JobObjectExtendedLimitInformation)` enables `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; `GetHandleInformation` rejects any inheritable handle. `CreateProcessW` creates the intended worker in `CREATE_SUSPENDED`, with `bInheritHandles=FALSE` and no Job breakaway. A typed `SuspendedJobWorker -> AssignedJobWorker -> RunningJobWorker` ensures the only `ResumeThread` entrypoint is *after* successful `AssignProcessToJobObject`. Any failure or abandoned pre-resume process is forcibly terminated and OS-waited on; no ARM or write authority is issued.

## Native falsifiers

An independent grandparent launches an independent launcher which opens JobObject and creates an OS worker *suspended*. Grandparent obtains a kernel PROCESS wait handle before allowing launcher to continue, but never obtains the Job handle. The worker must not publish any file before assignment/resume. After native resume it executes and writes a disposable marker using write, sync_all on the original writable handle, close, rename. Grandparent hard-kills the launcher with real Windows `TerminateProcess`, verifies the worker's kernel PROCESS wait becomes signaled when the last Job handle disappears, and does not rely on PID text for an exit proof.

A second test deliberately refuses to assign a suspended worker; typed guard must terminate/reap without ever resuming or publishing writer marker. Every test uses disposable temporary fixture roots only. Windows GitHub Actions runs both tests and strict format, Clippy and Rust 1.91.

## Explicit limitations

- Not linked to real pinned FsStore actor/StoreLease, physical Bao, durable checkpoint, protected IPC, Akula File Gate or any peer grant.
- Assignment of nested jobs may fail under some host/runner restrictions, in which case **refuse and terminate before execution**, never bypass the Job.
- This test excludes malicious child code already running before containment through ordinary CreateProcessW but does not prove exclusion of every inherited/out-of-band process handle in a production daemon. No verified parent identity handoff. It provides no Windows directory power-loss durability.
- No equivalent Linux production pidfd origin binding or cancellation-safe real actor startup/shutdown.
- Safe `custody/src/lib.rs` is unchanged. #26 remains OPEN, G2-06 and Akula Production File Gate HOLD.

## Windows APIs
- https://learn.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createprocessw
- https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information
