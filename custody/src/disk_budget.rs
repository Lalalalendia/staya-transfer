//! STY-G2-05g: conservative logical-length snapshot of a QUIESCENT pinned
//! FsStore partial directory, under an existing cooperative OS StoreLease.
//!
//! Logical lengths include sparse holes; they are NOT physical disk usage,
//! free-space information, or an enforcement mechanism for writes in progress.
//! Unsupported entries, path substitution, overflow or excess usage HOLD.

use crate::{StoreLease, forbid_link, validate_walk};
use std::{collections::HashSet, fs, io};

pub const HARD_MAX_ENTRIES: usize = 512;
pub const HARD_MAX_OBJECTS: usize = 128;
pub const HARD_MAX_LOGICAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiskLimits {
    pub max_entries: usize,
    pub max_objects: usize,
    pub max_logical_bytes: u64,
}

impl DiskLimits {
    pub fn validate(self) -> io::Result<()> {
        if self.max_entries == 0
            || self.max_entries > HARD_MAX_ENTRIES
            || self.max_objects == 0
            || self.max_objects > HARD_MAX_OBJECTS
            || self.max_logical_bytes == 0
            || self.max_logical_bytes > HARD_MAX_LOGICAL_BYTES
        {
            return Err(invalid("unsupported quiescent disk budget"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiskSnapshot {
    pub entries: usize,
    pub objects: usize,
    /// Sum of file metadata lengths, including sparse holes.
    pub logical_bytes: u64,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn parse_name(name: &str) -> io::Result<&str> {
    let (stem, suffix) = name
        .rsplit_once('.')
        .ok_or_else(|| invalid("unrecognized partial object filename"))?;
    if !matches!(suffix, "data" | "obao4" | "sizes4" | "bitfield")
        || stem.len() != 64
        || !stem.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("unsupported pinned FsStore partial filename"));
    }
    Ok(stem)
}

/// Inspect only the already-quiescent pinned partial data directory.
///
/// Caller must hold OS ownership from before FsStore opened until AFTER it is
/// closed; the directory is not an adversarial multiwriter shared location.
/// This bounds metadata enumeration and recorded logical lengths only.
/// NEVER use the returned snapshot to authorize range reuse or File Gate.
pub fn inspect_quiescent_partial_files(
    owner: &StoreLease,
    limits: DiskLimits,
) -> io::Result<DiskSnapshot> {
    limits.validate()?;
    owner.validate_fence()?;
    let directory = owner.canonical_root().join("data");
    validate_walk(&directory)?;
    let directory_meta = fs::symlink_metadata(&directory)?;
    forbid_link(&directory_meta)?;
    if !directory_meta.is_dir() {
        return Err(invalid("pinned FsStore data path is not a directory"));
    }

    let mut entries = 0usize;
    let mut logical_bytes = 0u64;
    let mut roots = HashSet::new();
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        entries = entries
            .checked_add(1)
            .ok_or_else(|| invalid("data directory entry count overflow"))?;
        if entries > limits.max_entries {
            return Err(invalid("quiescent FsStore entry quota exceeded"));
        }
        let path = entry.path();
        validate_walk(&path)?;
        let meta = fs::symlink_metadata(&path)?;
        forbid_link(&meta)?;
        if !meta.is_file() {
            return Err(invalid("unexpected non-file partial storage entry"));
        }
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| invalid("non-UTF8 partial storage filename"))?;
        let stem = parse_name(name)?;
        if !roots.contains(stem) {
            if roots.len() >= limits.max_objects {
                return Err(invalid("quiescent FsStore object quota exceeded"));
            }
            roots.try_reserve(1)
                .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "object count allocation"))?;
            roots.insert(stem.to_owned());
        }
        logical_bytes = logical_bytes
            .checked_add(meta.len())
            .ok_or_else(|| invalid("logical disk byte count overflow"))?;
        if logical_bytes > limits.max_logical_bytes {
            return Err(invalid("quiescent FsStore logical byte quota exceeded"));
        }
    }
    owner.validate_fence()?;
    Ok(DiskSnapshot {
        entries,
        objects: roots.len(),
        logical_bytes,
    })
}
