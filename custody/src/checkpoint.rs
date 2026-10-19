//! STY-G2-04a: append-only crash-fail-closed *claims* about retained ranges.
//!
//! No entry from this module is a verified byte range or a durable FsStore
//! receipt. A recovered claim is only a candidate for independent physical
//! Bao authentication under an exclusive lease; its checksum is NOT a MAC.
//! This lab assumes an isolated private directory and cooperative OS locking.
//! Malicious simultaneous pathname replacement requires stronger fd custody.

use crate::StoreLease;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const MAGIC: &[u8; 8] = b"STYG2CP1";
const PREFIX: &str = ".staya-cp-";
const TEMP_PREFIX: &str = ".staya-cp-tmp-";
const SUFFIX: &str = ".bin";
const PAYLOAD_BYTES: usize = 76;
const RECORD_BYTES: usize = PAYLOAD_BYTES + 32;
/// Absolute upper bound until G2-05 quotas and retirement are implemented.
pub const MAX_CLAIMS: u64 = 128;
/// Bounded number of interrupted, unpublished checkpoints in one private store.
pub const MAX_PENDING_CLAIMS: usize = 32;
/// Bound top-level directory scans even if irrelevant or malicious names exist.
pub const MAX_ROOT_ENTRIES: usize = 512;
/// The tested pinned 0.103.1 pre-order Bao encoding, 16 KiB groups.
pub const IROH_PREORDER_16K: u32 = 1;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// A persisted range claim, **not** a cryptographic authorization to resume.
/// Independently check source, content bytes, and full-root Bao before skipping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointClaim {
    pub sequence: u64,
    pub content_root: [u8; 32],
    pub object_len: u64,
    pub bao_profile: u32,
    pub start: u64,
    pub end: u64,
}

impl CheckpointClaim {
    pub fn validate(&self) -> io::Result<()> {
        if self.sequence == 0 || self.sequence > MAX_CLAIMS {
            return Err(invalid("checkpoint sequence exceeds capacity"));
        }
        if self.bao_profile != IROH_PREORDER_16K {
            return Err(invalid("checkpoint Bao profile unsupported"));
        }
        if self.object_len == 0 || self.start >= self.end || self.end > self.object_len {
            return Err(invalid("checkpoint range invalid"));
        }
        // A checkpoint covers complete pinned Bao groups only. The last,
        // possibly short group is permitted only at exact end-of-object.
        const GROUP: u64 = 16 * 1024;
        if !self.start.is_multiple_of(GROUP)
            || (self.end != self.object_len && !self.end.is_multiple_of(GROUP))
        {
            return Err(invalid("checkpoint range not Bao-group aligned"));
        }
        Ok(())
    }
}

/// A *metadata-only* write-barrier report. Neither variant certifies that
/// iroh-blobs had synced its data/outboard, or that File Gate can publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataBarrier {
    /// File synced, renamed to a fresh generation, and parent dir synced.
    FileAndDirectorySynced,
    /// Windows does not expose a portable directory fsync in std.
    /// Crash/power-loss durability is NOT acknowledged by this variant.
    FileSyncedDirectoryUnproven,
}

fn file_name(sequence: u64) -> String {
    format!("{PREFIX}{sequence:016}{SUFFIX}")
}

fn encode(claim: CheckpointClaim) -> [u8; RECORD_BYTES] {
    let mut out = [0u8; RECORD_BYTES];
    out[..8].copy_from_slice(MAGIC);
    out[8..16].copy_from_slice(&claim.sequence.to_le_bytes());
    out[16..48].copy_from_slice(&claim.content_root);
    out[48..56].copy_from_slice(&claim.object_len.to_le_bytes());
    out[56..60].copy_from_slice(&claim.bao_profile.to_le_bytes());
    out[60..68].copy_from_slice(&claim.start.to_le_bytes());
    out[68..76].copy_from_slice(&claim.end.to_le_bytes());
    let checksum = *blake3::hash(&out[..PAYLOAD_BYTES]).as_bytes();
    out[PAYLOAD_BYTES..].copy_from_slice(&checksum);
    out
}

fn decode(bytes: &[u8]) -> io::Result<CheckpointClaim> {
    if bytes.len() != RECORD_BYTES || &bytes[..8] != MAGIC {
        return Err(invalid("checkpoint record version or length invalid"));
    }
    if &bytes[PAYLOAD_BYTES..] != blake3::hash(&bytes[..PAYLOAD_BYTES]).as_bytes() {
        return Err(invalid("checkpoint metadata checksum mismatch"));
    }
    let to_u64 = |pos: usize| -> u64 {
        u64::from_le_bytes(
            bytes[pos..pos + 8]
                .try_into()
                .expect("checked fixed record"),
        )
    };
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes[16..48]);
    let claim = CheckpointClaim {
        sequence: to_u64(8),
        content_root: root,
        object_len: to_u64(48),
        bao_profile: u32::from_le_bytes(bytes[56..60].try_into().expect("fixed record")),
        start: to_u64(60),
        end: to_u64(68),
    };
    claim.validate()?;
    Ok(claim)
}

fn validate_file(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(invalid("checkpoint path is not a regular file"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(invalid("checkpoint is a Windows reparse point"));
        }
    }
    if meta.len() != RECORD_BYTES as u64 {
        return Err(invalid(
            "checkpoint physical byte length differs from record",
        ));
    }
    Ok(())
}

/// Fail closed on private-root directory explosion, malformed pending paths and
/// unexpected pending sizes BEFORE inspecting trusted checkpoint candidates.
///
/// A pending record is NEVER a verified/committed generation. There is no
/// automatic deletion, even when an interrupted process left a valid prefix.
/// The caller must hold the cooperative OS lease; hostile path races remain
/// outside this lab until fd-relative and Windows HANDLE-relative custody.
fn bounded_pending_records(owner: &StoreLease) -> io::Result<Vec<(std::path::PathBuf, u64)>> {
    owner.validate_fence()?;
    let mut scanned = 0usize;
    let mut pending = Vec::new();
    let mut pending_bytes = 0u64;
    for entry in fs::read_dir(owner.canonical_root())? {
        let entry = entry?;
        scanned += 1;
        if scanned > MAX_ROOT_ENTRIES {
            return Err(invalid("private checkpoint root entry quota exceeded"));
        }
        let filename = entry.file_name();
        let Some(name) = filename.to_str() else {
            continue;
        };
        if !name.starts_with(TEMP_PREFIX) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid("pending checkpoint is not a regular file"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid("pending checkpoint Windows reparse point"));
            }
        }
        // Partially-written records must be no larger than the fixed record.
        // Never allocate memory proportional to a recovered filename or length.
        if metadata.len() > RECORD_BYTES as u64 {
            return Err(invalid("pending checkpoint length exceeds fixed record"));
        }
        pending_bytes = pending_bytes
            .checked_add(metadata.len())
            .ok_or_else(|| invalid("pending checkpoint size overflow"))?;
        if pending_bytes > (MAX_PENDING_CLAIMS * RECORD_BYTES) as u64 {
            return Err(invalid("pending checkpoint byte budget exceeded"));
        }
        pending.push((path, metadata.len()));
        if pending.len() > MAX_PENDING_CLAIMS {
            return Err(invalid("pending checkpoint count exceeded"));
        }
    }
    owner.validate_fence()?;
    Ok(pending)
}

/// Bounded cleanup of only unpublished .staya-cp-tmp-* names in a cooperative,
/// private, *quiescent* checkpoint directory. Never touches FsStore blob files,
/// the custody lock, or published checkpoint generations.
///
/// This is not safe against malicious concurrent path swaps and does NOT grant
/// a durable result or resume authority. If bounds/types are violated, remove
/// NOTHING: the operator must inspect the private directory first. Windows
/// unlink persistence across sudden power loss is not claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrphanCleanup {
    pub removed: usize,
    pub bytes: u64,
}

pub fn cleanup_pending_records(owner: &StoreLease) -> io::Result<OrphanCleanup> {
    let candidates = bounded_pending_records(owner)?;
    let mut outcome = OrphanCleanup {
        removed: 0,
        bytes: 0,
    };
    for (path, expected_length) in candidates {
        owner.validate_fence()?;
        let actual = fs::symlink_metadata(&path)?;
        if !actual.is_file()
            || actual.file_type().is_symlink()
            || actual.len() != expected_length
        {
            return Err(invalid("pending checkpoint changed during cleanup"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if actual.file_attributes() & 0x400 != 0 {
                return Err(invalid("pending checkpoint replaced by reparse point"));
            }
        }
        fs::remove_file(&path)?;
        outcome.removed += 1;
        outcome.bytes += expected_length;
    }
    #[cfg(unix)]
    {
        fs::File::open(owner.canonical_root())?.sync_all()?;
    }
    owner.validate_fence()?;
    Ok(outcome)
}

/// Enumerate **untrusted** metadata candidates from an existing private store.
/// Every returned entry MUST pass a later independent physical Bao audit before
/// it can be used by the missing-range scheduler. No VerifiedRanges is returned.
pub fn read_candidates(
    owner: &StoreLease,
    trusted_root: [u8; 32],
    trusted_size: u64,
    trusted_profile: u32,
) -> io::Result<Vec<CheckpointClaim>> {
    owner.validate_fence()?;
    if trusted_size == 0 || trusted_profile != IROH_PREORDER_16K {
        return Err(invalid("unrecognized trusted checkpoint identity"));
    }
    // Fail closed on orphan temp floods before interpreting durable claims.
    // Interrupted temp files are ignored for skip/admission, not for quotas.
    let _pending = bounded_pending_records(owner)?;
    let mut discovered = Vec::new();
    let mut scanned = 0usize;
    for entry in fs::read_dir(owner.canonical_root())? {
        let entry = entry?;
        scanned += 1;
        if scanned > MAX_ROOT_ENTRIES {
            return Err(invalid("private checkpoint root entry quota exceeded"));
        }
        let filename = entry.file_name();
        let Some(name) = filename.to_str() else {
            continue;
        };
        if name.starts_with(TEMP_PREFIX) {
            // Interrupted temporary records must not be published.
            continue;
        }
        if !name.starts_with(PREFIX) {
            continue;
        }
        let sequence = name
            .strip_prefix(PREFIX)
            .and_then(|s| s.strip_suffix(SUFFIX))
            .and_then(|s| {
                if s.len() == 16 {
                    s.parse::<u64>().ok()
                } else {
                    None
                }
            })
            .ok_or_else(|| invalid("unexpected checkpoint filename in private store"))?;
        if sequence == 0 || sequence > MAX_CLAIMS {
            return Err(invalid("checkpoint quota/sequence violated"));
        }
        validate_file(&entry.path())?;
        let record = fs::read(entry.path())?;
        let claim = decode(&record)?;
        if claim.sequence != sequence
            || claim.content_root != trusted_root
            || claim.object_len != trusted_size
            || claim.bao_profile != trusted_profile
        {
            return Err(invalid("checkpoint identity differs from trusted manifest"));
        }
        discovered.push(claim);
        if discovered.len() > MAX_CLAIMS as usize {
            return Err(invalid("checkpoint count exceeds quota"));
        }
    }
    discovered.sort_unstable_by_key(|x| x.sequence);
    for (index, claim) in discovered.iter().enumerate() {
        if claim.sequence != index as u64 + 1 {
            return Err(invalid("missing/duplicate checkpoint generation"));
        }
    }
    owner.validate_fence()?;
    Ok(discovered)
}

/// Publish a *new immutable generation*. This does NOT certify the contents of
/// the referenced FsStore data. Caller must FIRST do independently verified
/// Bao import and ensure its backend data/outboard is physically durable.
/// G2-04b will connect those barriers and independently audit them.
/// A failed post-rename barrier may leave a candidate; that never implies trust.
pub fn publish_candidate(
    owner: &StoreLease,
    claim: CheckpointClaim,
) -> io::Result<MetadataBarrier> {
    claim.validate()?;
    let existing = read_candidates(
        owner,
        claim.content_root,
        claim.object_len,
        claim.bao_profile,
    )?;
    if claim.sequence != existing.len() as u64 + 1 {
        return Err(invalid("nonmonotonic or reused checkpoint generation"));
    }
    owner.validate_fence()?;
    let final_path = owner.canonical_root().join(file_name(claim.sequence));
    if fs::symlink_metadata(&final_path).is_ok() {
        return Err(invalid("immutable checkpoint generation already exists"));
    }
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("clock before unix epoch"))?
        .as_nanos();
    let temporary = owner.canonical_root().join(format!(
        "{TEMP_PREFIX}{:016}-{}-{unique}",
        claim.sequence,
        std::process::id(),
    ));
    // No following links or truncating an existing filename. Any orphaned
    // temporary record is ignored at restart; cleanup/quota is later G2-05.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&encode(claim))?;
    file.sync_all()?;
    drop(file);
    owner.validate_fence()?;
    // Unique generation names avoid unsafe overwrite of an existing "current".
    // Pathname races against hostile actors are NOT solved by this check.
    fs::rename(&temporary, &final_path)?;
    owner.validate_fence()?;
    #[cfg(unix)]
    {
        // Linux/macOS same-volume directory barrier. Fail closed if unsupported.
        fs::File::open(owner.canonical_root())?.sync_all()?;
        owner.validate_fence()?;
        Ok(MetadataBarrier::FileAndDirectorySynced)
    }
    #[cfg(windows)]
    {
        // Do not claim metadata directory durability through a no-op.
        Ok(MetadataBarrier::FileSyncedDirectoryUnproven)
    }
}
