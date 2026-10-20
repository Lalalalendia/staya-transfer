//! Narrow Linux kernel syscall boundary for the G2-05h3e laboratory.
//!
//! PR_SET_PDEATHSIG is installed in the child between fork and exec.
//! A pidfd is separately used as a stable exit witness. This is NOT yet
//! a secure authenticated parent identity or production trust boundary:
//! getppid()/pidfd_open() cannot conclusively eliminate every PID-reuse or
//! parent-thread race during setup on every kernel.

use std::{
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        raw::{c_int, c_long, c_ulong},
        unix::process::CommandExt,
    },
    process::Command,
};

const PR_SET_PDEATHSIG: c_int = 1;
const SIGKILL: c_ulong = 9;
const POLLIN: i16 = 0x0001;
const POLLHUP: i16 = 0x0010;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYS_PIDFD_OPEN: c_long = 434;

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    fn prctl(option: c_int, ...) -> c_int;
    fn getppid() -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
    fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
}

/// Installs a non-catchable signal on creator-thread death before exec.
///
/// # Safety rationale
/// CommandExt::pre_exec is unsafe because only async-signal-safe operations
/// may run after fork. The closure does only direct libc/kernel syscalls,
/// integer checks, and constructs io::Error from errno on failure.
pub fn require_parent_death_before_exec(command: &mut Command, expected_parent: u32) {
    let expected = expected_parent as c_int;
    // SAFETY: the closure captures only an integer, performs only C syscalls,
    // and neither allocates nor acquires a mutex in its successful path.
    unsafe {
        command.pre_exec(move || {
            // SAFETY: prctl's fixed option and four integer arguments match
            // Linux PR_SET_PDEATHSIG. SIGKILL ends the child on parent-thread
            // death even if it has entered a blocking syscall.
            if prctl(
                PR_SET_PDEATHSIG,
                SIGKILL,
                0 as c_ulong,
                0 as c_ulong,
                0 as c_ulong,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: getppid has no pointer arguments or ownership effects.
            if getppid() != expected {
                return Err(io::Error::from_raw_os_error(3)); // ESRCH => fail closed
            }
            Ok(())
        });
    }
}

/// A Linux pidfd is tied to the kernel process identity, not reusable PID text.
pub struct PidFd(OwnedFd);

impl PidFd {
    pub fn open(pid: u32) -> io::Result<Self> {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            // SAFETY: SYS_pidfd_open expects pid_t and unsigned int flags.
            // Return -1 indicates errno; success transfers an owned fd.
            let raw = unsafe { syscall(SYS_PIDFD_OPEN, pid as c_int, 0u32) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let raw =
                c_int::try_from(raw).map_err(|_| io::Error::other("pidfd descriptor overflow"))?;
            // SAFETY: a successful pidfd_open returned a new owned descriptor.
            Ok(Self(unsafe { OwnedFd::from_raw_fd(raw) }))
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            let _ = pid;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pidfd syscall architecture unsupported: HOLD",
            ))
        }
    }

    pub fn exited(&self, timeout_ms: i32) -> io::Result<bool> {
        let mut entry = PollFd {
            fd: self.0.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: a valid pointer to one initialized pollfd is supplied;
        // poll does not take ownership of the underlying pidfd.
        let result = unsafe { poll(&mut entry, 1, timeout_ms) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result == 0 {
            return Ok(false);
        }
        if entry.revents & (POLLIN | POLLHUP) != 0 {
            return Ok(true);
        }
        Err(io::Error::other("unexpected pidfd poll state: HOLD"))
    }
}

/// Bind to the actual current parent before any test worker file access.
///
/// The parent PID check on both sides of pidfd_open is useful but NOT a
/// complete proof against a kernel startup race or rapid PID reuse.
pub fn bind_actual_parent(expected: u32) -> io::Result<PidFd> {
    // SAFETY: getppid is an async-signal-safe syscall.
    if unsafe { getppid() } != expected as c_int {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "parent identity changed before native worker ARM",
        ));
    }
    let witness = PidFd::open(expected)?;
    if unsafe { getppid() } != expected as c_int || witness.exited(0)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "parent was no longer alive at native worker binding",
        ));
    }
    Ok(witness)
}
