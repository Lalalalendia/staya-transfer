//! STY-G2-04b: experimental quiescent pinned FsStore file barriers.
//!
//! This must only run *after* the owning FsStore actor has been stopped. The
//! physical Bao audit callback is supplied by the caller; it MUST use pinned
//! bao_tree::valid_ranges against a trusted immutable root. This module cannot
//! prove callback correctness or prevent hostile same-inode writers. Neither
//! a successful callback nor a checkpoint grants Akula File Gate permission.

use crate::{
    StoreLease,
    checkpoint::{CheckpointClaim, MetadataBarrier},
};
use std::{io, path::PathBuf};

#[cfg(unix)]
use crate::{forbid_link, validate_walk};
#[cfg(unix)]
use same_file::Handle;
#[cfg(unix)]
use std::{
    fs::{self, File, OpenOptions},
    path::Path,
};

/// Expected pinned external partial-store backing files (not a new backend).
#[derive(Debug)]
pub struct PartialPaths {
    pub data: PathBuf,
    pub outboard: PathBuf,
    pub sizes: PathBuf,
    pub bitfield: PathBuf,
}

#[cfg(unix)]
fn paths(owner: &StoreLease, claim: CheckpointClaim) -> PartialPaths {
    let hex = claim
        .content_root
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let root = owner.canonical_root().join("data");
    PartialPaths {
        data: root.join(format!("{hex}.data")),
        outboard: root.join(format!("{hex}.obao4")),
        sizes: root.join(format!("{hex}.sizes4")),
        bitfield: root.join(format!("{hex}.bitfield")),
    }
}

#[cfg(unix)]
struct HeldBackingFile {
    path: PathBuf,
    _file: File,
    identity: Handle,
    length: u64,
}

#[cfg(unix)]
fn checked_open(path: &Path) -> io::Result<HeldBackingFile> {
    validate_walk(path)?;
    let meta = fs::symlink_metadata(path)?;
    forbid_link(&meta)?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FsStore partial backing entry is not a file",
        ));
    }
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let identity = Handle::from_file(file.try_clone()?)?;
    if identity != Handle::from_path(path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FsStore backing path replaced during open",
        ));
    }
    let len = file.metadata()?.len();
    file.sync_all()?;
    Ok(HeldBackingFile {
        path: path.to_path_buf(),
        _file: file,
        identity,
        length: len,
    })
}

/// Linux/Unix laboratory transaction around a *quiescent* FsStore:
///
/// 1. Require cooperative store ownership and an existing private data dir.
/// 2. Pin and sync the data, Bao outboard, sizes4 and bitfield physical files.
/// 3. Sync the data directory, then run caller's independent physical Bao audit.
/// 4. Recheck physical identities/owner; publish a versioned metadata **claim**.
///
/// On Windows, reject before publication: directory data durability barriers
/// are not yet established. This function is intentionally NOT an Akula/FS
/// write gate, not a safe adversarial pathname-swap guard, and not SIGKILL proof.
pub fn publish_after_quiescent_audit(
    owner: &StoreLease,
    claim: CheckpointClaim,
    audit: impl FnOnce(&PartialPaths) -> io::Result<()>,
) -> io::Result<MetadataBarrier> {
    claim.validate()?;
    owner.validate_fence()?;
    #[cfg(not(unix))]
    {
        let _ = audit;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "FsStore directory durability on Windows is not proven",
        ))
    }
    #[cfg(unix)]
    {
        const MAX_AUDIT_RANGE: u64 = 16 * 1024 * 1024;
        if claim.end - claim.start > MAX_AUDIT_RANGE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "partial audit range exceeds laboratory limit",
            ));
        }
        let backings = paths(owner, claim);
        let data_dir = owner.canonical_root().join("data");
        validate_walk(&data_dir)?;
        let names = [
            &backings.data,
            &backings.outboard,
            &backings.sizes,
            &backings.bitfield,
        ];
        let held = names
            .into_iter()
            .map(|path| checked_open(path))
            .collect::<io::Result<Vec<_>>>()?;
        if held[0].length < claim.end
            || held[1].length == 0
            || held[2].length < 8
            || held[3].length == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incomplete FsStore partial data/outboard/sizes/bitfield",
            ));
        }
        File::open(&data_dir)?.sync_all()?;
        audit(&backings)?;
        owner.validate_fence()?;
        for file in &held {
            validate_walk(&file.path)?;
            if file.identity != Handle::from_path(&file.path)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "FsStore partial path identity changed during audit",
                ));
            }
        }
        // The caller-supplied verifier must have proved the requested range.
        // A saved journal entry is still only a candidate at next restart.
        crate::checkpoint::publish_candidate(owner, claim)
    }
}

/// Re-audit an existing *untrusted candidate* after the owning FsStore actor
/// is QUIESCENT. The caller must independently authenticate persisted Bao and
/// byte ranges against a locally pinned BLAKE3 root and exact object length.
///
/// This is a private, cooperative Unix LAB helper, not a VerifiedCheckpoint,
/// retained-byte skip token, trusted ACK, or File Gate authorization.
/// On Windows retained-range durability remains unproven: refuse by design.
/// Hostile concurrent path swaps are not solved by cooperative ownership.
pub fn reaudit_untrusted_candidate_backings(
    owner: &StoreLease,
    claim: CheckpointClaim,
    audit: impl FnOnce(&PartialPaths) -> io::Result<()>,
) -> io::Result<()> {
    claim.validate()?;
    owner.validate_fence()?;
    #[cfg(not(unix))]
    {
        let _ = audit;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows durable retained-range reuse has not been proven",
        ))
    }
    #[cfg(unix)]
    {
        let candidates = crate::checkpoint::read_candidates(
            owner,
            claim.content_root,
            claim.object_len,
            claim.bao_profile,
        )?;
        if !candidates.contains(&claim) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "matching checkpoint candidate not found",
            ));
        }
        let backings = paths(owner, claim);
        let names = [
            &backings.data,
            &backings.outboard,
            &backings.sizes,
            &backings.bitfield,
        ];
        let held = names
            .into_iter()
            .map(|path| checked_open(path))
            .collect::<io::Result<Vec<_>>>()?;
        if held[0].length < claim.end
            || held[1].length == 0
            || held[2].length < 8
            || held[3].length == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing or truncated FsStore physical sidecar",
            ));
        }
        // The callback is required to verify ACTUAL data + sparse Bao
        // outboard against the caller's independently trusted full root.
        audit(&backings)?;
        owner.validate_fence()?;
        for file in &held {
            validate_walk(&file.path)?;
            if file.identity != Handle::from_path(&file.path)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "physical FsStore backing identity changed during audit",
                ));
            }
        }
        Ok(())
    }
}
