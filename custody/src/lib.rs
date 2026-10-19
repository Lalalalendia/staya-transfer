#![forbid(unsafe_code)]
//! STY-G2-03: experimental cooperative single-process filesystem custody.
//!
//! This is a separate Rust 1.91+ harness; Akula File Gate and the Rust 1.85
//! Staya core do NOT use it yet. Holding this lock does not authenticate data,
//! guarantee fsync, or stop a malicious writer who ignores advisory locks.
//! A change of lockfile or directory identity must prevent further admission.

use same_file::Handle;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io,
    path::{Component, Path, PathBuf},
};

const LOCK_NAME: &str = ".staya-writer.lock";

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn forbid_link(metadata: &Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(invalid("symlink in store or custody path"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid("Windows reparse point in store or custody path"));
        }
    }
    Ok(())
}

/// Refuse symlinks (and Windows reparse points) at every existing component.
/// Reject lexical parent paths rather than silently resolving another store.
/// This alone cannot prevent a hostile concurrent pathname-swap race.
fn validate_walk(input: &Path) -> io::Result<()> {
    let absolute = if input.is_absolute() {
        input.to_path_buf()
    } else {
        std::env::current_dir()?.join(input)
    };
    let mut walked = PathBuf::new();
    for component in absolute.components() {
        if component == Component::ParentDir {
            return Err(invalid("parent components forbidden in store root"));
        }
        walked.push(component.as_os_str());
        if matches!(component, Component::Normal(_)) {
            forbid_link(&fs::symlink_metadata(&walked)?)?;
        }
    }
    Ok(())
}

/// A non-cloneable file-lock lease: all cooperative writers must hold one.
/// Keep the File alive for the entire FsStore writer session.
#[derive(Debug)]
pub struct StoreLease {
    canonical_root: PathBuf,
    root_identity: Handle,
    lock_path: PathBuf,
    lock_identity: Handle,
    _held_exclusive_lock: File,
}

impl StoreLease {
    /// Open an existing locally configured private store root.
    /// Never accept this pathname from untrusted network metadata.
    pub fn acquire(root: impl AsRef<Path>) -> io::Result<Self> {
        validate_walk(root.as_ref())?;
        let canonical_root = fs::canonicalize(root)?;
        validate_walk(&canonical_root)?;
        if !fs::metadata(&canonical_root)?.is_dir() {
            return Err(invalid("store root must be an existing directory"));
        }
        let root_identity = Handle::from_path(&canonical_root)?;
        let lock_path = canonical_root.join(LOCK_NAME);
        // Reject a pre-existing symlink or unexpected file type before open.
        match fs::symlink_metadata(&lock_path) {
            Ok(m) => {
                forbid_link(&m)?;
                if !m.is_file() {
                    return Err(invalid("custody path must be a regular file"));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }

        // No truncation and never delete a stale-looking lockfile. OS lock
        // lifetime, not file existence or PID text, supplies cooperation.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        let lock_identity = Handle::from_file(file.try_clone()?)?;
        file.try_lock().map_err(io::Error::from)?;
        let guard = Self {
            canonical_root,
            root_identity,
            lock_path,
            lock_identity,
            _held_exclusive_lock: file,
        };
        guard.validate_fence()?;
        Ok(guard)
    }

    /// Recheck all physical identities before handing off any staging write.
    /// A successful check is not an atomic proof against adversarial swaps
    /// after the check; that stronger gate needs pinned fd-relative paths.
    pub fn validate_fence(&self) -> io::Result<()> {
        validate_walk(&self.canonical_root)?;
        let md = fs::symlink_metadata(&self.lock_path)?;
        forbid_link(&md)?;
        if !md.is_file() {
            return Err(invalid("custody lockfile no longer regular"));
        }
        let root_now = Handle::from_path(&self.canonical_root)?;
        if root_now != self.root_identity {
            return Err(invalid("store directory identity changed"));
        }
        let lock_now = Handle::from_path(&self.lock_path)?;
        if lock_now != self.lock_identity {
            return Err(invalid("lockfile inode/identity replaced while lease held"));
        }
        Ok(())
    }

    /// Only diagnostic/read-only; no caller may move/delete this lockfile.
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }
}
