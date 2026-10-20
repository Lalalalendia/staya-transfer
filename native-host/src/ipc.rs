//! G2-05h3g1: Linux-only first-party inherited socket IPC laboratory.
//!
//! A kernel-created anonymous Unix socket, SO_PEERCRED and pre-exec parent
//! death protection gate a single bounded ARM/ACK before ANY test file access.
//! This is not production trust: no worker executable attestation, Windows
//! transport, clean shutdown, FsStore ownership or Akula File Gate is here.

use crate::linux::{PidFd, bind_actual_parent, require_parent_death_before_exec};
use std::{
    ffi::c_void,
    fs::File,
    io::{self, Read, Write},
    mem::size_of,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        raw::c_int,
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Child, Command, ExitStatus},
    time::Duration,
};

const FD: c_int = 3;
const SOL_SOCKET: c_int = 1;
const SO_PEERCRED: c_int = 17;
const F_SETFD: c_int = 2;
const MAGIC: [u8; 4] = *b"STYI";
const VERSION: [u8; 2] = 1u16.to_be_bytes();
const SIZE: usize = 40;
const ARM: u8 = 1;
const ACK: u8 = 2;
const IO_TIMEOUT: Duration = Duration::from_secs(8);

#[repr(C)]
#[derive(Default)]
struct UCred {
    pid: c_int,
    uid: u32,
    gid: u32,
}

unsafe extern "C" {
    fn dup2(oldfd: c_int, newfd: c_int) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn getsockopt(
        socket: c_int,
        level: c_int,
        option_name: c_int,
        option_value: *mut c_void,
        option_len: *mut u32,
    ) -> c_int;
    fn geteuid() -> u32;
    fn getegid() -> u32;
}

fn deny(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

fn frame(kind: u8, nonce: &[u8; 32]) -> [u8; SIZE] {
    let mut data = [0u8; SIZE];
    data[..4].copy_from_slice(&MAGIC);
    data[4..6].copy_from_slice(&VERSION);
    data[6] = kind;
    data[8..].copy_from_slice(nonce);
    data
}

fn parse_frame(
    data: &[u8; SIZE],
    expected_kind: u8,
    expected_nonce: Option<&[u8; 32]>,
) -> io::Result<[u8; 32]> {
    if data[..4] != MAGIC
        || data[4..6] != VERSION
        || data[6] != expected_kind
        || data[7] != 0
    {
        return Err(deny("wrong IPC magic, version, command or reserved flags: HOLD"));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[8..]);
    if nonce == [0u8; 32] || expected_nonce.is_some_and(|expected| *expected != nonce) {
        return Err(deny("zero, mismatched or replayed IPC session: HOLD"));
    }
    Ok(nonce)
}

fn require_socket_creator(fd: RawFd, expected_parent: u32) -> io::Result<()> {
    let expected_pid =
        c_int::try_from(expected_parent).map_err(|_| deny("parent PID out of range"))?;
    let mut identity = UCred::default();
    let mut length =
        u32::try_from(size_of::<UCred>()).map_err(|_| deny("ucred size too large"))?;
    // SAFETY: the initialized ucred structure and length are valid writable
    // output buffers. Linux SO_PEERCRED reports kernel credentials captured
    // at the creation of the connected socketpair, not caller-provided text.
    if unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            SO_PEERCRED,
            (&raw mut identity).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if length != size_of::<UCred>() as u32 {
        return Err(deny("incorrect SO_PEERCRED kernel record length"));
    }
    // SAFETY: no pointers, process credentials obtained from the kernel.
    if identity.pid != expected_pid
        || identity.uid != unsafe { geteuid() }
        || identity.gid != unsafe { getegid() }
    {
        return Err(deny("inherited IPC socket creator does not match parent PID/UID/GID"));
    }
    Ok(())
}

/// Affine handshake proof. Possession does NOT grant filesystem write or
/// any transfer/checkpoint authorization. The pidfd must stay alive.
pub struct VerifiedParent {
    _pidfd: PidFd,
    _channel: UnixStream,
}

/// Must run before opening StoreLease or FsStore. FD=3 must come from a
/// first-party launcher; no caller-controlled pathname or TCP listener.
pub fn receive_parent_arm(expected_parent: u32) -> io::Result<VerifiedParent> {
    let witness = bind_actual_parent(expected_parent)?;
    // Do NOT use from_raw_fd before checking this is an actual Unix socket
    // and its kernel creator matches the expected live process identity.
    require_socket_creator(FD, expected_parent)?;
    // SAFETY: FD=3 has now been verified to be the inherited connected
    // socketpair endpoint. This function is the sole owner of that fd.
    let mut channel = unsafe { UnixStream::from_raw_fd(FD) };
    channel.set_read_timeout(Some(IO_TIMEOUT))?;
    channel.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut incoming = [0u8; SIZE];
    channel.read_exact(&mut incoming)?;
    let nonce = parse_frame(&incoming, ARM, None)?;
    if witness.exited(0)? {
        return Err(deny("parent died before IPC ARM"));
    }
    channel.write_all(&frame(ACK, &nonce))?;
    channel.flush()?;
    if witness.exited(0)? {
        return Err(deny("parent died before IPC ACK"));
    }
    Ok(VerifiedParent {
        _pidfd: witness,
        _channel: channel,
    })
}

/// Owns the actual Child OS handle and exclusive anonymous socket endpoint.
/// A failed ARM or accidental Drop destroys the child; it NEVER grants
/// clean-quiescence/verified-checkpoint authority.
pub struct UnarmedWorker {
    child: Child,
    operator: UnixStream,
}

impl Drop for UnarmedWorker {
    fn drop(&mut self) {
        // Lab-only emergency cleanup; NOT bounded production supervisor.
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

/// Only first-party Command creation is permitted. No FD=3 is ever sent to
/// an unrelated peer or obtained through a public socket path.
pub fn spawn_unarmed(mut command: Command) -> io::Result<UnarmedWorker> {
    let (operator, worker_end) = UnixStream::pair()?;
    operator.set_read_timeout(Some(IO_TIMEOUT))?;
    operator.set_write_timeout(Some(IO_TIMEOUT))?;
    let source_fd = worker_end.as_raw_fd();
    require_parent_death_before_exec(&mut command, std::process::id());
    // SAFETY: the pre-exec callback contains only direct async-signal-safe
    // integer syscalls. It copies the private socket endpoint to fixed FD=3.
    // F_SETFD(0) removes CLOEXEC on ONLY this endpoint for the trusted exec.
    unsafe {
        command.pre_exec(move || {
            if dup2(source_fd, FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            if fcntl(FD, F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    drop(worker_end); // no original worker endpoint remains in the launcher
    Ok(UnarmedWorker { child, operator })
}

impl UnarmedWorker {
    pub fn process_id(&self) -> u32 {
        self.child.id()
    }

    /// Strict one-shot typed promotion: failure kills/reaps the OS worker.
    pub fn arm(mut self) -> io::Result<ArmedWorker> {
        let mut nonce = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        if nonce == [0u8; 32] {
            return Err(deny("OS random session is zero"));
        }
        self.operator.write_all(&frame(ARM, &nonce))?;
        self.operator.flush()?;
        let mut reply = [0u8; SIZE];
        self.operator.read_exact(&mut reply)?;
        parse_frame(&reply, ACK, Some(&nonce))?;
        if PidFd::open(self.child.id())?.exited(0)? {
            return Err(deny("worker exited before authenticated IPC promotion"));
        }
        Ok(ArmedWorker(self))
    }
}

/// LAB-ONLY authorized-to-run marker, not a File Gate permission.
pub struct ArmedWorker(UnarmedWorker);

impl ArmedWorker {
    pub fn process_id(&self) -> u32 {
        self.0.process_id()
    }

    pub fn terminate_and_reap(mut self) -> io::Result<ExitStatus> {
        if self.0.child.try_wait()?.is_none() {
            self.0.child.kill()?;
        }
        self.0.child.wait()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_versioned_frames_fail_closed() {
        let nonce = [7u8; 32];
        let original = frame(ARM, &nonce);
        assert_eq!(parse_frame(&original, ARM, None).unwrap(), nonce);
        let mut bad = original;
        bad[0] ^= 1;
        assert!(parse_frame(&bad, ARM, None).is_err());
        let mut bad = original;
        bad[5] = 2;
        assert!(parse_frame(&bad, ARM, None).is_err());
        let mut bad = original;
        bad[6] = ACK;
        assert!(parse_frame(&bad, ARM, None).is_err());
        let mut bad = original;
        bad[7] = 1;
        assert!(parse_frame(&bad, ARM, None).is_err());
        assert!(parse_frame(&frame(ARM, &[0; 32]), ARM, None).is_err());
        assert!(parse_frame(&original, ARM, Some(&[8; 32])).is_err());
        let mut truncated = std::io::Cursor::new(&original[..SIZE - 1]);
        let mut exact = [0u8; SIZE];
        assert_eq!(
            truncated.read_exact(&mut exact).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn socket_kernel_identity_cannot_be_replaced_with_pid_text() {
        let (one, _two) = UnixStream::pair().unwrap();
        require_socket_creator(one.as_raw_fd(), std::process::id()).unwrap();
        assert!(require_socket_creator(one.as_raw_fd(), u32::MAX).is_err());
    }
}
