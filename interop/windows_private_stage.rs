//! G1j Windows-only private staging. Isolated Win32 FFI boundary.
//! A protected DACL is supplied *during* CreateDirectoryW, not after.
//! The caller uses a random, locally generated destination, never a peer path.
//! This is not proof against an adversary racing an ancestor directory swap.
#![deny(unsafe_op_in_unsafe_fn)]

use std::{
    ffi::c_void,
    fs, io,
    mem::size_of,
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
    ptr::null_mut,
};

type Handle = *mut c_void;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_USER: u32 = 1;
const SE_FILE_OBJECT: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const SE_DACL_PROTECTED: u16 = 0x1000;
const ACL_SIZE_INFORMATION: u32 = 2;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: *mut c_void,
    inherit_handle: i32,
}

#[repr(C)]
struct SidAndAttributes {
    sid: *mut c_void,
    _attributes: u32,
}

#[repr(C)]
struct AclSizeInformation {
    ace_count: u32,
    _bytes_in_use: u32,
    _bytes_free: u32,
}

#[repr(C)]
struct AceHeader {
    ace_type: u8,
    _ace_flags: u8,
    ace_size: u16,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn LocalFree(ptr: *mut c_void) -> *mut c_void;
    fn CreateDirectoryW(path: *const u16, security: *const SecurityAttributes) -> i32;
    #[cfg(test)]
    #[allow(dead_code, reason = "exercised by integration test crate, not the preview binary")]
    fn GetCurrentThread() -> Handle;
    #[cfg(test)]
    #[allow(dead_code, reason = "exercised by integration test crate, not the preview binary")]
    fn CreateFileW(
        name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security: *const c_void,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    #[cfg(test)]
    #[allow(dead_code, reason = "exercised by integration test crate, not the preview binary")]
    fn ImpersonateAnonymousToken(thread: Handle) -> i32;
    #[cfg(test)]
    #[allow(dead_code, reason = "exercised by integration test crate, not the preview binary")]
    fn RevertToSelf() -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        buffer: *mut c_void,
        len: u32,
        returned_len: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *const c_void, text: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        len: *mut u32,
    ) -> i32;
    fn GetNamedSecurityInfoW(
        object: *mut u16,
        object_type: u32,
        flags: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn GetSecurityDescriptorDacl(
        descriptor: *mut c_void,
        present: *mut i32,
        dacl: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    fn GetSecurityDescriptorControl(
        descriptor: *mut c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
    fn GetAclInformation(acl: *mut c_void, data: *mut c_void, len: u32, info_class: u32) -> i32;
    fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
}

struct OwnedHandle(Handle);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: OpenProcessToken supplied one owned, non-null handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct LocalMemory(*mut c_void);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        // SAFETY: only LocalAlloc-compatible buffers returned by Advapi32.
        let _ = unsafe { LocalFree(self.0) };
    }
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(invalid("embedded NUL in staging path"));
    }
    value.push(0);
    Ok(value)
}

fn wide_string(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn sid_string(sid: *const c_void) -> io::Result<String> {
    if sid.is_null() {
        return Err(invalid("missing Windows security SID"));
    }
    let mut output = null_mut();
    // SAFETY: caller supplies a SID owned by the security API, kept live
    // during this call, and Advapi32 allocates a separate output string.
    if unsafe { ConvertSidToStringSidW(sid, &mut output) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if output.is_null() {
        return Err(invalid("Windows returned no SID text"));
    }
    let memory = LocalMemory(output.cast());
    let mut len = 0;
    // SAFETY: ConvertSidToStringSidW returns a zero-terminated wide string
    // in a valid LocalAlloc buffer for the lifetime of memory.
    while unsafe { *output.add(len) } != 0 {
        len += 1;
        if len > 256 {
            return Err(invalid("unbounded SID string"));
        }
    }
    // SAFETY: length was measured in the same owned allocation.
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(output, len) })
        .map_err(|_| invalid("non-UTF16 SID text"))?;
    drop(memory);
    Ok(text)
}

fn current_user_sid() -> io::Result<String> {
    let mut handle = null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; OpenProcessToken
    // returns a new token handle which OwnedHandle closes.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if handle.is_null() {
        return Err(invalid("Windows token handle absent"));
    }
    let token = OwnedHandle(handle);
    let mut len = 0u32;
    // SAFETY: query required buffer size without a destination.
    let _ = unsafe { GetTokenInformation(token.0, TOKEN_USER, null_mut(), 0, &mut len) };
    if (len as usize) < size_of::<SidAndAttributes>() || len > 65_536 {
        return Err(invalid("Windows TokenUser size invalid"));
    }
    // Align to usize: TOKEN_USER begins with a pointer-aligned SID field.
    let mut storage = vec![0usize; (len as usize).div_ceil(size_of::<usize>())];
    // SAFETY: word-aligned allocation has at least len writable bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TOKEN_USER,
            storage.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if (len as usize) < size_of::<SidAndAttributes>() {
        return Err(invalid("Windows TokenUser truncated"));
    }
    // SAFETY: the response is a checked TokenUser header inside aligned storage.
    let header = unsafe { &*storage.as_ptr().cast::<SidAndAttributes>() };
    sid_string(header.sid.cast_const())
}

fn inspect_ancestors(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("private directory has no parent"))?;
    if !parent.is_absolute() {
        return Err(invalid("staging parent must be absolute"));
    }
    let mut walked = PathBuf::new();
    for component in parent.components() {
        if matches!(component, Component::ParentDir) {
            return Err(invalid("staging path contains a parent component"));
        }
        walked.push(component.as_os_str());
        if matches!(component, Component::Normal(_)) {
            let meta = fs::symlink_metadata(&walked)?;
            if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(invalid("reparse point or nondirectory staging ancestor"));
            }
        }
    }
    Ok(())
}

/// Validate actual DACL instead of assuming the supplied descriptor was used.
/// A protected directory has exactly current-user and SYSTEM full-control ACEs.
/// An inheriting output file is checked for the same two allowed principals.
fn verify_acl(path: &Path, must_be_protected: bool) -> io::Result<()> {
    let mut p = wide(path)?;
    let mut raw_dacl = null_mut();
    let mut raw_descriptor = null_mut();
    // SAFETY: output pointers are valid; a successful returned descriptor
    // owns its referenced DACL until LocalFree.
    let status = unsafe {
        GetNamedSecurityInfoW(
            p.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut raw_dacl,
            null_mut(),
            &mut raw_descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if raw_descriptor.is_null() {
        return Err(invalid("Windows returned no security descriptor"));
    }
    let _descriptor = LocalMemory(raw_descriptor);
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = null_mut();
    // SAFETY: descriptor is owned for the duration of this audit.
    if unsafe { GetSecurityDescriptorDacl(raw_descriptor, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || dacl.is_null() {
        return Err(invalid("missing or null staging DACL"));
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: output parameters and descriptor have valid lifetimes.
    if unsafe { GetSecurityDescriptorControl(raw_descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if must_be_protected && control & SE_DACL_PROTECTED == 0 {
        return Err(invalid("staging directory inherited an unsafe DACL"));
    }
    let mut info = AclSizeInformation {
        ace_count: 0,
        _bytes_in_use: 0,
        _bytes_free: 0,
    };
    // SAFETY: info is correctly sized for AclSizeInformation.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut info).cast(),
            size_of::<AclSizeInformation>() as u32,
            ACL_SIZE_INFORMATION,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if info.ace_count != 2 {
        return Err(invalid("staging ACL contains unexpected trustees"));
    }
    let expected_user = current_user_sid()?;
    let mut saw_user = false;
    let mut saw_system = false;
    for index in 0..info.ace_count {
        let mut ace = null_mut();
        // SAFETY: the ACL remains owned by the descriptor and index is bounded.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            return Err(invalid("malformed staging ACE"));
        }
        // SAFETY: GetAce returns a valid ACE header.
        let header = unsafe { &*ace.cast::<AceHeader>() };
        if header.ace_type != ACCESS_ALLOWED_ACE_TYPE || header.ace_size < 16 {
            return Err(invalid("non-allow or undersized staging ACE"));
        }
        // SAFETY: ACE header length ensures an aligned or unaligned mask slot.
        let mask = unsafe { std::ptr::read_unaligned((ace as *const u8).add(4).cast::<u32>()) };
        if mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS {
            return Err(invalid("staging owner ACE lacks full control"));
        }
        // SAFETY: ACCESS_ALLOWED_ACE stores its SID immediately after mask.
        let who = sid_string(unsafe { (ace as *const u8).add(8) }.cast())?;
        if who == expected_user && !saw_user {
            saw_user = true;
        } else if who == "S-1-5-18" && !saw_system {
            saw_system = true;
        } else {
            return Err(invalid("staging ACL contains unapproved trustee"));
        }
    }
    if !saw_user || !saw_system {
        return Err(invalid("owner and SYSTEM staging trustees not present"));
    }
    Ok(())
}

pub fn create_owner_only_directory(path: &Path) -> io::Result<()> {
    inspect_ancestors(path)?;
    let user = current_user_sid()?;
    // D:P means protected DACL, OI/CI carries the same private ACEs onto files.
    // No Everyone, Users, Authenticated Users or Administrators group grant.
    let sddl = wide_string(&format!("D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)"));
    let mut raw_descriptor = null_mut();
    // SAFETY: SDDL is NUL-terminated, pointer outlives the call and LocalFree.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut raw_descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if raw_descriptor.is_null() {
        return Err(invalid(
            "Windows private staging security descriptor absent",
        ));
    }
    let _descriptor = LocalMemory(raw_descriptor);
    let attr = SecurityAttributes {
        length: size_of::<SecurityAttributes>() as u32,
        descriptor: raw_descriptor,
        inherit_handle: 0,
    };
    let name = wide(path)?;
    // SAFETY: CreateDirectoryW atomically receives the explicit protected DACL.
    // Existing directory => failure; never widen a preexisting directory.
    if unsafe { CreateDirectoryW(name.as_ptr(), &attr) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // This guards simple ancestor reparse substitution. It is NOT a claim
    // of race-free pinned handle-relative filesystem custody.
    inspect_ancestors(path)?;
    verify_acl(path, true)
}

pub fn verify_owner_only_staged_file(path: &Path) -> io::Result<()> {
    verify_acl(path, false)
}

pub fn verify_owner_only_staging_root(path: &Path) -> io::Result<()> {
    verify_acl(path, true)
}

/// Real Windows access-denial test under a distinct built-in security principal.
/// This deliberately runs on a NEW OS thread so no Tokio worker can retain
/// anonymous impersonation after a failed syscall. A missing file or failure
/// to impersonate is NOT evidence of a protective DACL.
#[cfg(test)]
#[allow(dead_code, reason = "integration gate uses this on Windows; preview bin does not")]
pub fn prove_anonymous_file_read_denied(path: &Path) -> io::Result<()> {
    let owned = path.to_path_buf();
    std::thread::spawn(move || {
        let name = wide(&owned)?;
        // SAFETY: GetCurrentThread returns a pseudo-handle for this NEW thread.
        if unsafe { ImpersonateAnonymousToken(GetCurrentThread()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: path is zero terminated; opening requests actual data READ.
        // No handle is returned on failure, so no stale permission can be
        // confused with a successful anonymous read.
        let file = unsafe {
            CreateFileW(
                name.as_ptr(),
                0x8000_0000, // GENERIC_READ
                7,           // SHARE_READ | SHARE_WRITE | SHARE_DELETE
                null_mut(),
                3,    // OPEN_EXISTING
                0x80, // FILE_ATTRIBUTE_NORMAL
                null_mut(),
            )
        };
        let denied = if file as isize == -1 {
            Some(io::Error::last_os_error())
        } else {
            // SAFETY: only successful CreateFileW handles may be closed.
            let _ = unsafe { CloseHandle(file) };
            None
        };
        // SAFETY: revert the impersonation on the same dedicated thread.
        // If this fails, the detached thread exits immediately and caller HOLDs.
        if unsafe { RevertToSelf() } == 0 {
            return Err(invalid("anonymous security context failed to revert"));
        }
        match denied {
            Some(err) if err.raw_os_error() == Some(5) => Ok(()), // ERROR_ACCESS_DENIED
            Some(_) => Err(invalid("anonymous read failed for non-ACL reason")),
            None => Err(invalid("anonymous identity opened private staging file")),
        }
    })
    .join()
    .map_err(|_| invalid("anonymous access-check thread panicked"))?
}
