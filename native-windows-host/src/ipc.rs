//! STY-G2 Windows restricted named pipe OS identity + ARM/ACK laboratory.
//! NOT installed production IPC, a signed permission or a File Gate grant.

use crate::windows::ProcessWatcher;
use std::{
    ffi::{c_void, OsStr},
    fmt::Write as _,
    io,
    mem::size_of,
    os::windows::ffi::OsStrExt,
    ptr::{null_mut},
};

type Handle = *mut c_void;
const INVALID: Handle = -1isize as Handle;
const PIPE_ACCESS_DUPLEX: u32 = 3;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 8;
const GENERIC_READ_WRITE: u32 = 0xC000_0000;
const OPEN_EXISTING: u32 = 3;
const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
const TOKEN_QUERY: u32 = 8;
const TOKEN_USER: u32 = 1;
const ERROR_PIPE_CONNECTED: u32 = 535;
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;
const MAGIC: [u8; 4] = *b"STYW";
const VERSION: [u8; 2] = 1u16.to_be_bytes();
const FRAME_SIZE: usize = 40;
const ARM: u8 = 1;
const ACK: u8 = 2;

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: Handle,
    inherit: i32,
}
#[link(name="kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetLastError() -> u32;
    fn LocalFree(value: Handle) -> Handle;
    fn CloseHandle(value: Handle) -> i32;
    fn CreateNamedPipeW(name: *const u16, mode: u32, pipe_mode: u32, max: u32, out_size: u32, in_size: u32, default_timeout: u32, security: *const SecurityAttributes) -> Handle;
    fn ConnectNamedPipe(pipe: Handle, overlapped: Handle) -> i32;
    fn GetNamedPipeClientProcessId(pipe: Handle, pid: *mut u32) -> i32;
    fn GetNamedPipeServerProcessId(pipe: Handle, pid: *mut u32) -> i32;
    fn CreateFileW(name: *const u16, access: u32, share: u32, security: Handle, creation: u32, flags: u32, template: Handle) -> Handle;
    fn ReadFile(handle: Handle, buffer: Handle, len: u32, actual: *mut u32, overlapped: Handle) -> i32;
    fn WriteFile(handle: Handle, buffer: *const c_void, len: u32, actual: *mut u32, overlapped: Handle) -> i32;
}
#[link(name="advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, desired: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(token: Handle, class: u32, output: Handle, max: u32, actual: *mut u32) -> i32;
    fn ConvertSidToStringSidW(sid: Handle, wide_sid: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: *const u16, revision: u32, descriptor: *mut Handle, size: *mut u32) -> i32;
}
#[link(name="bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(algorithm: Handle, buffer: *mut u8, len: u32, flags: u32) -> i32;
}

fn deny(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(Some(0)).collect()
}
fn random(bytes: &mut [u8]) -> io::Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| deny("random buffer oversized"))?;
    // SAFETY: live writable buffer of precisely length bytes.
    let status = unsafe { BCryptGenRandom(null_mut(), bytes.as_mut_ptr(), length, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status != 0 {
        return Err(io::Error::other(format!("BCryptGenRandom NTSTATUS {status:#x}")));
    }
    Ok(())
}

struct Owned(Handle);
impl Owned {
    fn new(raw: Handle) -> io::Result<Self> {
        if raw.is_null() || raw == INVALID {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: only Windows-owned live handles are wrapped.
        let _ = unsafe { CloseHandle(self.0) };
    }
}
struct Local(Handle);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: SDDL and SID string allocated by LocalAlloc-compatible API.
        let _ = unsafe { LocalFree(self.0) };
    }
}

fn process_user_sid() -> io::Result<String> {
    let mut raw = null_mut();
    // SAFETY: the current process pseudo-handle and writable token pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Owned::new(raw)?;
    let mut needed = 0;
    // SAFETY: size-probe for TokenUser with no output buffer.
    let _ = unsafe { GetTokenInformation(token.0, TOKEN_USER, null_mut(), 0, &mut needed) };
    if needed < size_of::<Handle>() as u32 || needed > 64 * 1024 {
        return Err(deny("invalid TokenUser size"));
    }
    let mut bytes = vec![0u8; needed as usize];
    let mut actual = 0;
    // SAFETY: returned TokenUser structure stored in the allocated buffer.
    if unsafe { GetTokenInformation(token.0, TOKEN_USER, bytes.as_mut_ptr().cast(), needed, &mut actual) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if actual < size_of::<Handle>() as u32 {
        return Err(deny("truncated token user SID"));
    }
    // SAFETY: the first field of TOKEN_USER is SID_AND_ATTRIBUTES.Sid; avoid
    // assuming the Vec<u8> is pointer-aligned by using read_unaligned.
    let sid = unsafe { (bytes.as_ptr() as *const Handle).read_unaligned() };
    if sid.is_null() {
        return Err(deny("null Windows process SID"));
    }
    let mut sid_text = null_mut();
    // SAFETY: valid SID pointer refers to the live TokenUser buffer.
    if unsafe { ConvertSidToStringSidW(sid, &mut sid_text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _release = Local(sid_text.cast());
    let length = (0..256).position(|i| unsafe { *sid_text.add(i) == 0 })
        .ok_or_else(|| deny("SID string exceeded 255 UTF16 code units"))?;
    // SAFETY: NUL-terminated Windows text held alive by Local wrapper.
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, length) })
        .map_err(|_| deny("invalid Windows SID UTF16"))?;
    if !result.starts_with("S-1-") || !result.chars().all(|ch| ch == 'S' || ch == '-' || ch.is_ascii_digit()) {
        return Err(deny("invalid canonical process SID"));
    }
    Ok(result)
}
fn restricted_descriptor() -> io::Result<Local> {
    let sid = process_user_sid()?;
    // Explicit DACL: only current Windows account and LocalSystem.
    // Default pipe DACL grants Everyone read access; never accept it.
    let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})"));
    let mut out = null_mut();
    // SAFETY: valid NUL-terminated SDDL, revision 1 and writable descriptor.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut out, null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if out.is_null() {
        return Err(deny("missing security descriptor"));
    }
    Ok(Local(out))
}

fn frame(kind: u8, nonce: &[u8; 32]) -> [u8; FRAME_SIZE] {
    let mut data = [0u8; FRAME_SIZE];
    data[..4].copy_from_slice(&MAGIC);
    data[4..6].copy_from_slice(&VERSION);
    data[6] = kind;
    data[8..].copy_from_slice(nonce);
    data
}
fn verify(data: &[u8; FRAME_SIZE], kind: u8, expected: Option<&[u8; 32]>) -> io::Result<[u8; 32]> {
    if data[..4] != MAGIC || data[4..6] != VERSION || data[6] != kind || data[7] != 0 {
        return Err(deny("unknown STYW IPC protocol/command/flags"));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[8..]);
    if nonce == [0u8; 32] || expected.is_some_and(|n| *n != nonce) {
        return Err(deny("mismatched, repeated or zero IPC nonce"));
    }
    Ok(nonce)
}
fn write_frame(handle: Handle, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let mut n = 0;
        // SAFETY: synchronous Win32 call and writable length output.
        if unsafe { WriteFile(handle, bytes.as_ptr().cast(), bytes.len() as u32, &mut n, null_mut()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "IPC send zero"));
        }
        bytes = &bytes[n as usize..];
    }
    Ok(())
}
fn read_frame(handle: Handle, mut bytes: &mut [u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let mut n = 0;
        // SAFETY: synchronous Win32 call and writable buffers.
        if unsafe { ReadFile(handle, bytes.as_mut_ptr().cast(), bytes.len() as u32, &mut n, null_mut()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short IPC frame"));
        }
        let (_, remainder) = bytes.split_at_mut(n as usize);
        bytes = remainder;
    }
    Ok(())
}

/// Server is created by a first-party launcher before a suspended Job worker.
pub struct PendingPipe {
    handle: Owned,
    name: String,
}
pub struct ArmedPipe(Owned);
pub struct VerifiedParent(Owned);

impl PendingPipe {
    pub fn create() -> io::Result<Self> {
        let security = restricted_descriptor()?;
        let attributes = SecurityAttributes {
            length: size_of::<SecurityAttributes>() as u32,
            descriptor: security.0,
            inherit: 0,
        };
        let mut unique = [0u8; 16];
        random(&mut unique)?;
        let mut hex = String::new();
        for b in unique {
            write!(&mut hex, "{b:02x}").map_err(|_| deny("failed to encode pipe identity"))?;
        }
        let name = format!(r"\\.\pipe\staya-g2-05h3g3-{}-{hex}", std::process::id());
        let name_wide = wide(&name);
        // SAFETY: explicit DACL and first/local-only instance, no inherited pipe handle.
        let raw = unsafe {
            CreateNamedPipeW(
                name_wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                5000,
                &attributes,
            )
        };
        Ok(Self { handle: Owned::new(raw)?, name })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Connects once, checks actual kernel worker PID and nonce.
    /// Synchronous transport is LAB-ONLY; no production bounded cancellation.
    pub fn arm(self, expected_worker_pid: u32) -> io::Result<ArmedPipe> {
        // SAFETY: server handle is live; Windows may connect before this call.
        if unsafe { ConnectNamedPipe(self.handle.0, null_mut()) } == 0
            && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED
        {
            return Err(io::Error::last_os_error());
        }
        let mut actual = 0;
        // SAFETY: kernel supplies real connected client process identity.
        if unsafe { GetNamedPipeClientProcessId(self.handle.0, &mut actual) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if expected_worker_pid == 0 || actual != expected_worker_pid {
            return Err(deny("named pipe client != assigned Job worker PID"));
        }
        let witness = ProcessWatcher::open(expected_worker_pid)?;
        if witness.exited(0)? {
            return Err(deny("worker died before ARM"));
        }
        let mut challenge = [0u8; 32];
        random(&mut challenge)?;
        write_frame(self.handle.0, &frame(ARM, &challenge))?;
        let mut reply = [0u8; FRAME_SIZE];
        read_frame(self.handle.0, &mut reply)?;
        verify(&reply, ACK, Some(&challenge))?;
        if witness.exited(0)? {
            return Err(deny("worker died before nonce ACK"));
        }
        Ok(ArmedPipe(self.handle))
    }
}

/// Workers call this before any data write, and eventually before real FsStore
/// opening when separately wired. The expected launcher PID is never authority
/// alone: GetNamedPipeServerProcessId and a process-only kernel handle gate it.
pub fn receive_parent_arm(pipe_name: &str, expected_parent_pid: u32) -> io::Result<VerifiedParent> {
    let prefix = r"\\.\pipe\staya-g2-05h3g3-";
    if !pipe_name.starts_with(prefix)
        || pipe_name.len() > 180
        || !pipe_name[prefix.len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() || ch == '-')
    {
        return Err(deny("invalid fixed private pipe namespace"));
    }
    let pipe = wide(pipe_name);
    // SAFETY: local pipe client uses IDENTIFICATION SQOS to prevent untrusted
    // server from impersonating a higher-privilege worker token.
    let raw = unsafe {
        CreateFileW(
            pipe.as_ptr(),
            GENERIC_READ_WRITE,
            0,
            null_mut(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        )
    };
    let handle = Owned::new(raw)?;
    let mut actual_server = 0;
    // SAFETY: kernel returns PID of the server bound to THIS handle.
    if unsafe { GetNamedPipeServerProcessId(handle.0, &mut actual_server) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if expected_parent_pid == 0 || actual_server != expected_parent_pid {
        return Err(deny("pipe server is not launcher PID"));
    }
    let parent_witness = ProcessWatcher::open(expected_parent_pid)?;
    if parent_witness.exited(0)? {
        return Err(deny("launcher died before Windows IPC"));
    }
    let mut request = [0u8; FRAME_SIZE];
    read_frame(handle.0, &mut request)?;
    let nonce = verify(&request, ARM, None)?;
    if parent_witness.exited(0)? {
        return Err(deny("launcher died before nonce ACK"));
    }
    write_frame(handle.0, &frame(ACK, &nonce))?;
    if parent_witness.exited(0)? {
        return Err(deny("launcher died immediately after ACK"));
    }
    Ok(VerifiedParent(handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_nonce_fail_closed() {
        let nonce = [9u8; 32];
        let exact = frame(ARM, &nonce);
        assert_eq!(verify(&exact, ARM, None).unwrap(), nonce);
        assert!(verify(&exact, ACK, None).is_err());
        assert!(verify(&exact, ARM, Some(&[8u8; 32])).is_err());
        assert!(verify(&frame(ARM, &[0u8; 32]), ARM, None).is_err());
        let mut bad = exact;
        bad[0] ^= 1;
        assert!(verify(&bad, ARM, None).is_err());
        let mut bad = exact;
        bad[7] = 1;
        assert!(verify(&bad, ARM, None).is_err());
    }
    #[test]
    fn explicit_user_sid_dacl_and_unique_local_pipe() {
        assert!(process_user_sid().unwrap().starts_with("S-1-"));
        let _security = restricted_descriptor().unwrap();
        assert!(PendingPipe::create().unwrap().name().starts_with(r"\\.\pipe\staya-g2-05h3g3-"));
    }
}
