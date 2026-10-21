//! STY-G2-05h3g5: bounded Windows overlapped named-pipe operations.
//!
//! A pending OVERLAPPED and its data buffers must stay alive until the kernel
//! actually completes cancellation. CancelIoEx alone is NOT completion.
//! If a kernel operation does not settle after a bounded cancel grace period,
//! abort this LAB process instead of dropping memory still owned by the kernel.
//! No File Gate, production process supervisor or durable acknowledgment.

use std::{ffi::c_void, io, mem::size_of, ptr::null, time::Instant};

type RawHandle = *mut c_void;
const ERROR_IO_PENDING: u32 = 997;
const ERROR_PIPE_CONNECTED: u32 = 535;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const CANCEL_GRACE_MS: u32 = 2_000;

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: RawHandle,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateEventW(
        attributes: *const c_void,
        manual_reset: i32,
        initial_state: i32,
        name: *const u16,
    ) -> RawHandle;
    fn CloseHandle(handle: RawHandle) -> i32;
    fn GetLastError() -> u32;
    fn WaitForSingleObject(handle: RawHandle, millis: u32) -> u32;
    fn GetOverlappedResult(
        handle: RawHandle,
        overlapped: *mut Overlapped,
        transferred: *mut u32,
        wait: i32,
    ) -> i32;
    fn CancelIoEx(handle: RawHandle, overlapped: *mut Overlapped) -> i32;
    fn ConnectNamedPipe(pipe: RawHandle, overlapped: *mut Overlapped) -> i32;
    fn ReadFile(
        handle: RawHandle,
        buffer: *mut c_void,
        length: u32,
        received: *mut u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn WriteFile(
        handle: RawHandle,
        buffer: *const c_void,
        length: u32,
        written: *mut u32,
        overlapped: *mut Overlapped,
    ) -> i32;
}

struct Event(RawHandle);
impl Event {
    fn create() -> io::Result<Self> {
        // SAFETY: valid arguments create a private, manual-reset kernel event.
        let handle = unsafe { CreateEventW(null(), 1, 0, null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }
}
impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: the handle is kernel-created and owned by this call only.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "Windows named-pipe ARM exceeded bounded deadline: HOLD",
    )
}

fn cancel_and_drain(handle: RawHandle, overlapped: &mut Overlapped, event: &Event) {
    // SAFETY: same file/operation pointer as submitted. The cancellation is
    // only a request; even ERROR_NOT_FOUND can mean normal completion raced it.
    let _ = unsafe { CancelIoEx(handle, overlapped) };
    // SAFETY: manual-reset event belongs exclusively to this operation.
    let result = unsafe { WaitForSingleObject(event.0, CANCEL_GRACE_MS) };
    if result != WAIT_OBJECT_0 {
        // Returning here would destroy OVERLAPPED and buffers while the kernel
        // may still read/write them. This disposable first-party process MUST
        // terminate instead. Job close remains the worker death fallback.
        std::process::abort();
    }
    let mut transferred = 0u32;
    // SAFETY: after the event signals, the OVERLAPPED operation has finished;
    // drain completion even if ERROR_OPERATION_ABORTED or successful race.
    let _ = unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, 0) };
}

fn completed_bytes(handle: RawHandle, overlapped: &mut Overlapped) -> io::Result<u32> {
    let mut transferred = 0u32;
    // SAFETY: the OS signaled completion; buffers and OVERLAPPED stay alive.
    if unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(transferred)
}

/// One Win32 operation. The callback may borrow user buffers for the entire
/// call; it may NEVER escape or return while kernel I/O is still pending.
fn operation(
    handle: RawHandle,
    deadline: Instant,
    pipe_connected_is_success: bool,
    begin: impl FnOnce(*mut Overlapped) -> i32,
) -> io::Result<u32> {
    let event = Event::create()?;
    let mut overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: event.0,
    };
    assert_eq!(
        size_of::<Overlapped>(),
        if cfg!(target_pointer_width = "64") {
            32
        } else {
            20
        },
        "Win32 OVERLAPPED FFI layout mismatch"
    );
    let completed = begin(&mut overlapped);
    if completed != 0 {
        return completed_bytes(handle, &mut overlapped);
    }
    // SAFETY: only GetLastError immediately after the failing Win32 call.
    let error = unsafe { GetLastError() };
    if pipe_connected_is_success && error == ERROR_PIPE_CONNECTED {
        return Ok(0);
    }
    if error != ERROR_IO_PENDING {
        return Err(io::Error::from_raw_os_error(error as i32));
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        cancel_and_drain(handle, &mut overlapped, &event);
        return Err(timed_out());
    }
    let millis = u32::try_from(remaining.as_millis())
        .unwrap_or(u32::MAX - 1)
        .max(1);
    // SAFETY: manual-reset event is kernel-owned and dedicated to this op.
    match unsafe { WaitForSingleObject(event.0, millis) } {
        WAIT_OBJECT_0 => completed_bytes(handle, &mut overlapped),
        WAIT_TIMEOUT => {
            cancel_and_drain(handle, &mut overlapped, &event);
            Err(timed_out())
        }
        _ => {
            // Do not drop an unobserved outstanding kernel operation even
            // after an unexpected wait failure.
            cancel_and_drain(handle, &mut overlapped, &event);
            Err(io::Error::other(
                "unexpected overlapped IPC wait state: HOLD",
            ))
        }
    }
}

pub(crate) fn connect(handle: RawHandle, deadline: Instant) -> io::Result<()> {
    operation(handle, deadline, true, |overlapped| {
        // SAFETY: overlapped is live through kernel completion, handle is a
        // server named pipe created with FILE_FLAG_OVERLAPPED.
        unsafe { ConnectNamedPipe(handle, overlapped) }
    })?;
    Ok(())
}

pub(crate) fn read_exact(
    handle: RawHandle,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let length = u32::try_from(bytes.len())
            .map_err(|_| io::Error::other("overlapped read frame oversized"))?;
        let n = operation(handle, deadline, false, |overlapped| {
            // SAFETY: the async ReadFile byte-count pointer is NULL per Win32
            // API contract. The buffer remains live until GetOverlappedResult
            // confirms completion or the whole lab process aborts.
            unsafe {
                ReadFile(
                    handle,
                    bytes.as_mut_ptr().cast(),
                    length,
                    std::ptr::null_mut(),
                    overlapped,
                )
            }
        })? as usize;
        if n == 0 || n > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Windows named-pipe incomplete/zero frame: HOLD",
            ));
        }
        let (_, rest) = bytes.split_at_mut(n);
        bytes = rest;
    }
    Ok(())
}

pub(crate) fn write_all(handle: RawHandle, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        let length = u32::try_from(bytes.len())
            .map_err(|_| io::Error::other("overlapped write frame oversized"))?;
        let n = operation(handle, deadline, false, |overlapped| {
            // SAFETY: immutable borrowed buffer stays live and unmoved until
            // the kernel returns a completed result or the process aborts.
            unsafe {
                WriteFile(
                    handle,
                    bytes.as_ptr().cast(),
                    length,
                    std::ptr::null_mut(),
                    overlapped,
                )
            }
        })? as usize;
        if n == 0 || n > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Windows named-pipe zero/invalid frame write: HOLD",
            ));
        }
        bytes = &bytes[n..];
    }
    Ok(())
}
