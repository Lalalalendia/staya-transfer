//! G2-04a: immutable checkpoint CLAIMS, never reusable Bao proof.
//! Linux/Unix directory barriers only. Windows refuses publication until a
//! platform-specific durability barrier is independently verified.
//! Cooperative StoreLease, not adversarial FD-relative custody or File Gate.

use crate::{forbid_link, validate_walk, StoreLease};
use same_file::Handle;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
};
#[cfg(unix)]
use std::io::Write;

const HEADER: &[u8; 8] = b"STYG2CP1";
const TRAILER: &[u8; 8] = b"STYEND01";
const RECORD_SIZE: usize = 88;
const GROUP: u64 = 16 * 1024;
const MAX_RANGE: u64 = 16 * 1024 * 1024;

fn invalid(s: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Claim {
    pub root: [u8; 32],
    pub size: u64,
    pub start: u64,
    pub end: u64,
    pub generation: u64,
}

impl Claim {
    fn check(self) -> io::Result<()> {
        if self.generation == 0 || self.size == 0 || self.start >= self.end
            || self.end > self.size || self.end - self.start > MAX_RANGE
            || self.start % GROUP != 0
            || (self.end != self.size && self.end % GROUP != 0)
        {
            return Err(invalid("invalid local checkpoint extent"));
        }
        Ok(())
    }

    fn encode(self) -> [u8; RECORD_SIZE] {
        let mut b = [0u8; RECORD_SIZE];
        b[..8].copy_from_slice(HEADER);
        b[8..12].copy_from_slice(&1u32.to_le_bytes()); // schema
        b[12..16].copy_from_slice(&1u32.to_le_bytes()); // Bao profile
        b[16..48].copy_from_slice(&self.root);
        b[48..56].copy_from_slice(&self.size.to_le_bytes());
        b[56..64].copy_from_slice(&self.start.to_le_bytes());
        b[64..72].copy_from_slice(&self.end.to_le_bytes());
        b[72..80].copy_from_slice(&self.generation.to_le_bytes());
        b[80..88].copy_from_slice(TRAILER);
        b
    }

    fn decode(b: &[u8; RECORD_SIZE]) -> io::Result<Self> {
        if &b[..8] != HEADER || &b[80..88] != TRAILER
            || u32::from_le_bytes(b[8..12].try_into().unwrap()) != 1
            || u32::from_le_bytes(b[12..16].try_into().unwrap()) != 1
        {
            return Err(invalid("unsupported or torn checkpoint envelope"));
        }
        let c = Self {
            root: b[16..48].try_into().unwrap(),
            size: u64::from_le_bytes(b[48..56].try_into().unwrap()),
            start: u64::from_le_bytes(b[56..64].try_into().unwrap()),
            end: u64::from_le_bytes(b[64..72].try_into().unwrap()),
            generation: u64::from_le_bytes(b[72..80].try_into().unwrap()),
        };
        c.check()?;
        Ok(c)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reopen {
    NeedsFreshPhysicalBaoAudit(Claim),
}

/// Pinned partial FsStore paths, derived ONLY from the locally trusted root.
pub struct PartialPaths {
    pub data: PathBuf,
    pub outboard: PathBuf,
    pub sizes: PathBuf,
}

fn to_hex(b: [u8; 32]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

fn paths(lease: &StoreLease, c: Claim) -> (PartialPaths, PathBuf, PathBuf) {
    let hex = to_hex(c.root);
    let base = lease.canonical_root().join("data");
    let files = PartialPaths {
        data: base.join(format!("{hex}.data")),
        outboard: base.join(format!("{hex}.obao4")),
        sizes: base.join(format!("{hex}.sizes4")),
    };
    let prefix = format!(".staya-g2-{hex}-{:016x}", c.generation);
    (
        files,
        lease.canonical_root().join(format!("{prefix}.pending")),
        lease.canonical_root().join(format!("{prefix}.checkpoint")),
    )
}

fn checked_readwrite(path: &Path) -> io::Result<(File, Handle)> {
    validate_walk(path)?;
    let m = fs::symlink_metadata(path)?;
    forbid_link(&m)?;
    if !m.is_file() {
        return Err(invalid("partial storage is not a regular file"));
    }
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let id = Handle::from_file(file.try_clone()?)?;
    if id != Handle::from_path(path)? {
        return Err(invalid("file identity changed during open"));
    }
    Ok((file, id))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// Under a cooperative OS lease, fsync physical partial data/outboard/sizes,
/// require a separate physical audit callback, then publish one immutable claim.
/// The caller MUST quiesce the upstream FsStore actor first. The audit callback
/// must independently check the actual Bao bytes against a locally trusted root.
/// Neither this function nor a marker authorizes skipping a byte on reopen.
/// Windows returns Unsupported BEFORE publication.
pub fn publish_after_audit(
    lease: &StoreLease,
    claim: Claim,
    audit: impl FnOnce(&PartialPaths) -> io::Result<()>,
) -> io::Result<()> {
    claim.check()?;
    lease.validate_fence()?;
    #[cfg(not(unix))]
    {
        let _ = audit;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows checkpoint directory barrier not independently proven",
        ));
    }
    #[cfg(unix)]
    {
        let (parts, pending, final_path) = paths(lease, claim);
        validate_walk(&lease.canonical_root().join("data"))?;
        let names = [&parts.data, &parts.outboard, &parts.sizes];
        let mut held = Vec::with_capacity(3);
        let mut identities = Vec::with_capacity(3);
        for path in names {
            let (file, id) = checked_readwrite(path)?;
            held.push(file);
            identities.push(id);
        }
        if held[0].metadata()?.len() < claim.end
            || held[1].metadata()?.len() == 0
            || held[2].metadata()?.len() < 8
        {
            return Err(invalid("partial FsStore file is missing backing bytes"));
        }
        for file in &held {
            file.sync_all()?;
        }
        sync_directory(&lease.canonical_root().join("data"))?;
        audit(&parts)?;
        for (path, identity) in names.iter().zip(&identities) {
            validate_walk(path)?;
            if Handle::from_path(path)? != *identity {
                return Err(invalid("backing file identity changed during audit"));
            }
        }
        lease.validate_fence()?;
        // No replacement or reuse of stale pending files; only new generations.
        let mut staged = OpenOptions::new()
            .write(true).create_new(true).open(&pending)?;
        staged.write_all(&claim.encode())?;
        staged.flush()?;
        staged.sync_all()?;
        lease.validate_fence()?;
        for (path, identity) in names.iter().zip(&identities) {
            if Handle::from_path(path)? != *identity {
                return Err(invalid("backing file was replaced during publication"));
            }
        }
        // hard_link creates an immutable new name atomically without replacing
        // an existing generation on Unix or Windows.
        fs::hard_link(&pending, &final_path)?;
        sync_directory(lease.canonical_root())?;
        fs::remove_file(&pending)?;
        sync_directory(lease.canonical_root())?;
        lease.validate_fence()?;
        Ok(())
    }
}

/// Even an intact published claim is an UNTRUSTED CANDIDATE. Its caller must
/// reacquire exclusive ownership and independently revalidate physical Bao
/// before treating the corresponding ranges as locally available.
pub fn inspect_untrusted(lease: &StoreLease, trusted: Claim) -> io::Result<Reopen> {
    trusted.check()?;
    lease.validate_fence()?;
    let (_, _, target) = paths(lease, trusted);
    validate_walk(&target)?;
    let m = fs::symlink_metadata(&target)?;
    forbid_link(&m)?;
    if !m.is_file() || m.len() != RECORD_SIZE as u64 {
        return Err(invalid("torn, oversized or non-file checkpoint"));
    }
    let mut file = File::open(&target)?;
    let id = Handle::from_file(file.try_clone()?)?;
    let mut b = [0u8; RECORD_SIZE];
    file.read_exact(&mut b)?;
    if id != Handle::from_path(&target)? {
        return Err(invalid("checkpoint identity changed while reading"));
    }
    let found = Claim::decode(&b)?;
    if found != trusted {
        return Err(invalid("checkpoint differs from trusted object/extent"));
    }
    lease.validate_fence()?;
    Ok(Reopen::NeedsFreshPhysicalBaoAudit(found))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture() -> (PathBuf, Claim) {
        let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("staya-g2-04-{}-{t}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("data")).unwrap();
        let c = Claim {
            root: [0x41; 32], size: 131_072, start: 0, end: 32_768, generation: 1,
        };
        let lease = StoreLease::acquire(&root).unwrap();
        let (p, _, _) = paths(&lease, c);
        fs::write(p.data, vec![0xC5; 32_768]).unwrap();
        fs::write(p.outboard, vec![0xA5; 256]).unwrap();
        fs::write(p.sizes, c.size.to_le_bytes()).unwrap();
        (root, c)
    }

    fn fixture_audit(p: &PartialPaths) -> io::Result<()> {
        if fs::read(&p.data)? != vec![0xC5; 32_768]
            || fs::metadata(&p.outboard)?.len() != 256
        {
            return Err(invalid("disposable fixture changed"));
        }
        Ok(())
    }

    #[test]
    fn envelope_rejects_corruption_and_unaligned_ranges() {
        let (_, c) = fixture();
        assert_eq!(Claim::decode(&c.encode()).unwrap(), c);
        let mut corrupt = c.encode();
        corrupt[0] ^= 4;
        assert!(Claim::decode(&corrupt).is_err());
        corrupt = c.encode();
        corrupt[87] ^= 8;
        assert!(Claim::decode(&corrupt).is_err());
        let mut wrong = c;
        wrong.end = 33_333;
        assert!(wrong.check().is_err());
        wrong = c;
        wrong.generation = 0;
        assert!(wrong.check().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn clean_close_reopen_is_only_candidate_and_tamper_holds() {
        let (root, c) = fixture();
        let lease = StoreLease::acquire(&root).unwrap();
        publish_after_audit(&lease, c, fixture_audit).unwrap();
        assert_eq!(inspect_untrusted(&lease, c).unwrap(), Reopen::NeedsFreshPhysicalBaoAudit(c));
        drop(lease);
        let second = StoreLease::acquire(&root).unwrap();
        assert_eq!(inspect_untrusted(&second, c).unwrap(), Reopen::NeedsFreshPhysicalBaoAudit(c));
        let (p, _, marker) = paths(&second, c);
        fs::write(&p.data, vec![0; 32_768]).unwrap();
        assert!(fixture_audit(&p).is_err());
        assert!(matches!(inspect_untrusted(&second, c).unwrap(), Reopen::NeedsFreshPhysicalBaoAudit(_)));
        let mut mark = OpenOptions::new().write(true).open(marker).unwrap();
        mark.write_all(b"X").unwrap();
        mark.sync_all().unwrap();
        assert!(inspect_untrusted(&second, c).is_err());
        drop(second);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn failure_and_stale_names_cannot_publish() {
        let (root, c) = fixture();
        let lease = StoreLease::acquire(&root).unwrap();
        assert!(publish_after_audit(&lease, c, |_| Err(invalid("audit denied"))).is_err());
        assert!(inspect_untrusted(&lease, c).is_err());
        publish_after_audit(&lease, c, fixture_audit).unwrap();
        assert!(publish_after_audit(&lease, c, fixture_audit).is_err());
        let mut next = c;
        next.generation = 2;
        let (_, pending, _) = paths(&lease, next);
        fs::write(pending, b"torn").unwrap();
        assert!(publish_after_audit(&lease, next, fixture_audit).is_err());
        assert!(inspect_untrusted(&lease, next).is_err());
        drop(lease);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(not(unix))]
    #[test]
    fn windows_refuses_unproven_directory_durability() {
        let (root, c) = fixture();
        let lease = StoreLease::acquire(&root).unwrap();
        assert_eq!(
            publish_after_audit(&lease, c, fixture_audit).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(inspect_untrusted(&lease, c).is_err());
        drop(lease);
        fs::remove_dir_all(root).unwrap();
    }
}
