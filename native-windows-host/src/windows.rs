//! STY-G2-05h3f: Windows native suspended-creation + JobObject laboratory.
//!
//! Only this standalone crate contains native unsafe/FFI. All process handles
//! are RAII-owned; a failed assignment/resume terminates and reaps the still
//! suspended worker. This is NOT yet an FsStore owner or authorized File Gate.

use std::{
    ffi::{OsStr, OsString, c_void},
    io,
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr::null,
};

type RawHandle = *mut c_void;

const CREATE_SUSPENDED: u32 = 0x0000_0004;
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
const SYNCHRONIZE: u32 = 0x0010_0000;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const WAIT_FAILED: u32 = 0xffff_ffff;

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    lp_reserved: *mut u16,
    lp_desktop: *mut u16,
    lp_title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    reserved2_len: u16,
    reserved2: *mut u8,
    std_in: RawHandle,
    std_out: RawHandle,
    std_err: RawHandle,
}

#[repr(C)]
struct ProcessInformation {
    process: RawHandle,
    thread: RawHandle,
    process_id: u32,
    thread_id: u32,
}

#[repr(C)]
struct BasicLimitInformation {
    process_user_time: i64,
    job_user_time: i64,
    flags: u32,
    min_working_set: usize,
    max_working_set: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}

#[repr(C)]
struct IoCounters {
    read_operations: u64,
    write_operations: u64,
    other_operations: u64,
    read_bytes: u64,
    write_bytes: u64,
    other_bytes: u64,
}

#[repr(C)]
struct ExtendedLimitInformation {
    basic: BasicLimitInformation,
    io: IoCounters,
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory: usize,
    peak_job_memory: usize,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> RawHandle;
    fn SetInformationJobObject(
        job: RawHandle,
        info_class: i32,
        info: *const c_void,
        info_size: u32,
    ) -> i32;
    fn GetHandleInformation(handle: RawHandle, flags: *mut u32) -> i32;
    fn CreateProcessW(
        app: *const u16,
        command: *mut u16,
        process_attributes: *const c_void,
        thread_attributes: *const c_void,
        inherit_handles: i32,
        creation_flags: u32,
        environment: *const c_void,
        directory: *const u16,
        startup: *mut StartupInfoW,
        info: *mut ProcessInformation,
    ) -> i32;
    fn AssignProcessToJobObject(job: RawHandle, process: RawHandle) -> i32;
    fn ResumeThread(thread: RawHandle) -> u32;
    fn TerminateProcess(process: RawHandle, exit_code: u32) -> i32;
    fn WaitForSingleObject(handle: RawHandle, millis: u32) -> u32;
    fn OpenProcess(desired_access: u32, inherit: i32, pid: u32) -> RawHandle;
    fn CloseHandle(handle: RawHandle) -> i32;
}

struct OwnedHandle(RawHandle);

impl OwnedHandle {
    fn from_kernel(raw: RawHandle) -> io::Result<Self> {
        if raw.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: only kernel-created, uniquely-owned handles reach this type.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// A process-only handle, never a JobObject handle. Holding this in the
/// independent grandparent cannot prevent KILL_ON_JOB_CLOSE.
pub struct ProcessWatcher(OwnedHandle);

impl ProcessWatcher {
    pub fn open(pid: u32) -> io::Result<Self> {
        // SAFETY: OpenProcess returns a new process handle on success.
        Self::from_handle(unsafe { OpenProcess(SYNCHRONIZE, 0, pid) })
    }

    fn from_handle(raw: RawHandle) -> io::Result<Self> {
        Ok(Self(OwnedHandle::from_kernel(raw)?))
    }

    pub fn exited(&self, millis: u32) -> io::Result<bool> {
        // SAFETY: the owned handle is live while the call runs.
        let result = unsafe { WaitForSingleObject(self.0.0, millis) };
        match result {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other(
                "unexpected Windows process wait state: HOLD",
            )),
        }
    }
}

struct ChildResources {
    job: OwnedHandle,
    process: OwnedHandle,
    thread: OwnedHandle,
    pid: u32,
}

// Explicit termination before releasing the last Job handle, even on
// partial setup failure. On TerminateProcess of the launcher (no Drop),
// the kernel closes the last Job handle and kills all associated workers.
impl Drop for ChildResources {
    fn drop(&mut self) {
        // SAFETY: this is a real uniquely owned process handle; process may
        // already be exited. Kernel job close remains a second kill barrier.
        let _ = unsafe { TerminateProcess(self.process.0, 73) };
        // SAFETY: bounded wait for an observed OS exit, not a clean receipt.
        let _ = unsafe { WaitForSingleObject(self.process.0, 2000) };
    }
}

pub struct SuspendedJobWorker(ChildResources);
pub struct AssignedJobWorker(ChildResources);
pub struct RunningJobWorker(ChildResources);

fn win_quote(value: &OsStr) -> Vec<u16> {
    // Windows argv convention: double every trailing slash before a quote,
    // escape literal quotes and quote the whole argument (including spaces).
    let mut out = vec![u16::from(b'"')];
    let mut backslashes = 0usize;
    for ch in value.encode_wide() {
        if ch == u16::from(b'\\') {
            backslashes += 1;
        } else {
            if ch == u16::from(b'"') {
                out.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2 + 1));
                out.push(ch);
            } else {
                out.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
                out.push(ch);
            }
            backslashes = 0;
        }
    }
    out.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
    out.push(u16::from(b'"'));
    out
}

impl SuspendedJobWorker {
    /// The only path creating a test worker. bInheritHandles=FALSE, no
    /// CREATE_BREAKAWAY_FROM_JOB, and the primary thread is suspended.
    pub fn create(executable: &Path, args: &[OsString]) -> io::Result<Self> {
        // SAFETY: NULL SECURITY_ATTRIBUTES creates a non-inheritable Job
        // Object. No global name or duplicated handle exists in this crate.
        let job = OwnedHandle::from_kernel(unsafe { CreateJobObjectW(null(), null()) })?;
        // SAFETY: the POD structure contains only integer fields.
        let mut limits: ExtendedLimitInformation = unsafe { std::mem::zeroed() };
        limits.basic.flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: size and pointer match JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
        if unsafe {
            SetInformationJobObject(
                job.0,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                (&raw const limits).cast(),
                u32::try_from(size_of::<ExtendedLimitInformation>())
                    .map_err(|_| io::Error::other("job limits size exceeds u32"))?,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut flags = 0u32;
        // SAFETY: owned handle and valid pointer to flags.
        if unsafe { GetHandleInformation(job.0, &mut flags) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & HANDLE_FLAG_INHERIT != 0 {
            return Err(io::Error::other(
                "inheritable JobObject handle forbidden: HOLD",
            ));
        }

        let mut command = win_quote(executable.as_os_str());
        for arg in args {
            command.push(u16::from(b' '));
            command.extend(win_quote(arg.as_os_str()));
        }
        command.push(0);
        let app: Vec<u16> = executable
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();

        // SAFETY: valid Windows STARTUPINFOW POD initialized with zeroes.
        let mut startup: StartupInfoW = unsafe { std::mem::zeroed() };
        startup.cb = u32::try_from(size_of::<StartupInfoW>())
            .map_err(|_| io::Error::other("startup size exceeds u32"))?;
        // SAFETY: kernel writes the complete PROCESS_INFORMATION record.
        let mut info: ProcessInformation = unsafe { std::mem::zeroed() };
        // SAFETY: application is NUL-terminated, command line is mutable,
        // all other pointers are valid or NULL, inheritance is explicitly OFF.
        if unsafe {
            CreateProcessW(
                app.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                0,
                CREATE_SUSPENDED,
                null(),
                null(),
                &mut startup,
                &mut info,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // Both handles are non-null on success according to CreateProcessW.
        // Construct and guard first: if a later step fails, Drop kills/reaps.
        let resources = ChildResources {
            job,
            process: OwnedHandle::from_kernel(info.process)?,
            thread: OwnedHandle::from_kernel(info.thread)?,
            pid: info.process_id,
        };
        Ok(Self(resources))
    }

    pub fn process_id(&self) -> u32 {
        self.0.pid
    }

    /// Consumes suspension and returns only an assigned-but-still-suspended
    /// child, or fails closed and kills it. No public resume on this type.
    pub fn assign(self) -> io::Result<AssignedJobWorker> {
        // SAFETY: real job and real suspended child; assignment must succeed
        // before any worker code is allowed to execute.
        if unsafe { AssignProcessToJobObject(self.0.job.0, self.0.process.0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(AssignedJobWorker(self.0))
    }
}

impl AssignedJobWorker {
    /// Starts the primary thread only after successful kernel assignment.
    pub fn resume(self) -> io::Result<RunningJobWorker> {
        // SAFETY: real primary-thread handle of our assigned child.
        if unsafe { ResumeThread(self.0.thread.0) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        Ok(RunningJobWorker(self.0))
    }
}

impl RunningJobWorker {
    pub fn process_id(&self) -> u32 {
        self.0.pid
    }
}
