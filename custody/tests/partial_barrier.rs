//! STY-G2-04b does NOT prove full FsStore crash survival.
use staya_custody_lab::{
    StoreLease,
    checkpoint::{
        CheckpointClaim, IROH_PREORDER_16K, MetadataBarrier, read_candidates,
    },
    partial_barrier::{PartialPaths, publish_after_quiescent_audit},
};
use std::{
    fs,
    io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const ROOT: [u8; 32] = [0x51; 32];
const SIZE: u64 = 1_048_593;

fn private_root() -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!(
        "staya-g2-04b-{}-{nonce}",
        std::process::id(),
    ));
    fs::create_dir(&path).unwrap();
    fs::create_dir(path.join("data")).unwrap();
    path
}

fn claim() -> CheckpointClaim {
    CheckpointClaim {
        sequence: 1,
        content_root: ROOT,
        object_len: SIZE,
        bao_profile: IROH_PREORDER_16K,
        start: 0,
        end: 32_768,
    }
}

fn fixture_paths(root: &Path) -> PartialPaths {
    let hex = "51".repeat(32);
    let data = root.join("data");
    PartialPaths {
        data: data.join(format!("{hex}.data")),
        outboard: data.join(format!("{hex}.obao4")),
        sizes: data.join(format!("{hex}.sizes4")),
        bitfield: data.join(format!("{hex}.bitfield")),
    }
}

fn seed(paths: &PartialPaths) {
    fs::write(&paths.data, vec![0xC5; 32_768]).unwrap();
    fs::write(&paths.outboard, vec![0xA5; 256]).unwrap();
    fs::write(&paths.sizes, SIZE.to_le_bytes()).unwrap();
    fs::write(&paths.bitfield, [1u8; 8]).unwrap();
}

fn fixture_audit(paths: &PartialPaths) -> io::Result<()> {
    if fs::read(&paths.data)? != vec![0xC5; 32_768] {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "data mismatch"));
    }
    if fs::metadata(&paths.outboard)?.len() != 256 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "outboard mismatch"));
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn all_four_backings_synced_before_callback_and_claim_publication() {
    let root = private_root();
    let paths = fixture_paths(&root);
    seed(&paths);
    let owner = StoreLease::acquire(&root).unwrap();
    let barrier = publish_after_quiescent_audit(&owner, claim(), fixture_audit).unwrap();
    assert_eq!(barrier, MetadataBarrier::FileAndDirectorySynced);
    assert_eq!(read_candidates(&owner, ROOT, SIZE, IROH_PREORDER_16K).unwrap(), vec![claim()]);
    drop(owner);
    let new_owner = StoreLease::acquire(&root).unwrap();
    let candidates = read_candidates(&new_owner, ROOT, SIZE, IROH_PREORDER_16K).unwrap();
    assert_eq!(candidates.len(), 1);
    // The metadata is still only a candidate. Refuse to use it after data
    // corruption until independent physical Bao verification succeeds again.
    fs::write(&paths.data, vec![0; 32_768]).unwrap();
    assert!(fixture_audit(&paths).is_err());
    assert_eq!(read_candidates(&new_owner, ROOT, SIZE, IROH_PREORDER_16K).unwrap().len(), 1);
    drop(new_owner);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn failed_audit_or_missing_backing_never_publishes_claim() {
    let root = private_root();
    let paths = fixture_paths(&root);
    seed(&paths);
    let owner = StoreLease::acquire(&root).unwrap();
    assert!(publish_after_quiescent_audit(&owner, claim(), |_| {
        Err(io::Error::new(io::ErrorKind::InvalidData, "no Bao proof"))
    }).is_err());
    assert!(read_candidates(&owner, ROOT, SIZE, IROH_PREORDER_16K).unwrap().is_empty());
    fs::remove_file(&paths.sizes).unwrap();
    assert!(publish_after_quiescent_audit(&owner, claim(), fixture_audit).is_err());
    assert!(read_candidates(&owner, ROOT, SIZE, IROH_PREORDER_16K).unwrap().is_empty());
    drop(owner);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn changed_backing_inode_during_audit_holds() {
    let root = private_root();
    let paths = fixture_paths(&root);
    seed(&paths);
    let owner = StoreLease::acquire(&root).unwrap();
    let moved = root.join("old-outboard");
    let result = publish_after_quiescent_audit(&owner, claim(), |_| {
        fs::rename(&paths.outboard, &moved)?;
        fs::write(&paths.outboard, vec![0xA5; 256])?;
        Ok(())
    });
    assert!(result.is_err());
    assert!(read_candidates(&owner, ROOT, SIZE, IROH_PREORDER_16K).unwrap().is_empty());
    drop(owner);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_rejects_unproven_directory_durability_before_creating_record() {
    let root = private_root();
    let paths = fixture_paths(&root);
    seed(&paths);
    let owner = StoreLease::acquire(&root).unwrap();
    let e = publish_after_quiescent_audit(&owner, claim(), fixture_audit).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    assert!(read_candidates(&owner, ROOT, SIZE, IROH_PREORDER_16K).unwrap().is_empty());
    drop(owner);
    fs::remove_dir_all(root).unwrap();
}
