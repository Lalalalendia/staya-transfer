//! STY-G2-05g: logical snapshot and true Linux ENOSPC publication refusal.
//! The /dev/full test exercises a real OS write failure at the audit callback,
//! NOT a full-disk write inside the upstream FsStore actor.

use staya_custody_lab::{
    StoreLease,
    disk_budget::{DiskLimits, inspect_quiescent_partial_files},
};
#[cfg(target_os = "linux")]
use staya_custody_lab::{
    checkpoint::{CheckpointClaim, IROH_PREORDER_16K, read_candidates},
    partial_barrier::{PartialPaths, publish_after_quiescent_audit},
};
#[cfg(target_os = "linux")]
use std::io::Write;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "linux")]
const ROOT: [u8; 32] = [0x61; 32];

fn private_root() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("staya-g2-05g-{}-{nonce}", std::process::id()));
    fs::create_dir(&path).unwrap();
    fs::create_dir(path.join("data")).unwrap();
    path
}

fn disk_limits() -> DiskLimits {
    DiskLimits {
        max_entries: 8,
        max_objects: 1,
        max_logical_bytes: 100_000,
    }
}

fn path(root: &Path, extension: &str) -> PathBuf {
    root.join("data")
        .join(format!("{}.{}", "61".repeat(32), extension))
}

fn seed(root: &Path) {
    fs::write(path(root, "data"), vec![0xC5; 32_768]).unwrap();
    fs::write(path(root, "obao4"), [0xA5; 128]).unwrap();
    fs::write(path(root, "sizes4"), [0x10; 16]).unwrap();
    fs::write(path(root, "bitfield"), [0x11; 8]).unwrap();
}

#[test]
fn quiescent_snapshot_refuses_excess_length_and_unknown_entries() {
    let root = private_root();
    let owner = StoreLease::acquire(&root).unwrap();
    seed(&root);
    let snapshot = inspect_quiescent_partial_files(&owner, disk_limits()).unwrap();
    assert_eq!(snapshot.objects, 1);
    assert_eq!(snapshot.entries, 4);
    assert_eq!(snapshot.logical_bytes, 32_920);
    let denied = DiskLimits {
        max_logical_bytes: snapshot.logical_bytes - 1,
        ..disk_limits()
    };
    assert!(inspect_quiescent_partial_files(&owner, denied).is_err());
    let denied_count = DiskLimits {
        max_entries: 3,
        ..disk_limits()
    };
    assert!(inspect_quiescent_partial_files(&owner, denied_count).is_err());
    assert_eq!(
        inspect_quiescent_partial_files(&owner, disk_limits()).unwrap(),
        snapshot
    );
    fs::write(root.join("data").join("unrecognized.tmp"), b"blocked").unwrap();
    assert!(inspect_quiescent_partial_files(&owner, disk_limits()).is_err());
    drop(owner);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn partial_directory_symlink_refused_without_reading_external_content() {
    use std::os::unix::fs::symlink;
    let root = private_root();
    let owner = StoreLease::acquire(&root).unwrap();
    seed(&root);
    fs::write(root.join("external-protected"), b"important").unwrap();
    let extra = path(&root, "data");
    fs::remove_file(&extra).unwrap();
    symlink(root.join("external-protected"), &extra).unwrap();
    assert!(inspect_quiescent_partial_files(&owner, disk_limits()).is_err());
    assert_eq!(
        fs::read(root.join("external-protected")).unwrap(),
        b"important"
    );
    drop(owner);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn actual_linux_enospc_during_physical_audit_never_publishes_checkpoint() {
    let root = private_root();
    let owner = StoreLease::acquire(&root).unwrap();
    seed(&root);
    let claim = CheckpointClaim {
        sequence: 1,
        content_root: ROOT,
        object_len: 1_048_593,
        bao_profile: IROH_PREORDER_16K,
        start: 0,
        end: 32_768,
    };
    let result = publish_after_quiescent_audit(&owner, claim, |_parts: &PartialPaths| {
        // The write really reaches Linux's ENOSPC-producing character device;
        // the pinned FsStore is NOT the writer for this controlled fault.
        let mut sink = fs::OpenOptions::new().write(true).open("/dev/full")?;
        sink.write_all(b"force ENOSPC during physical validation")?;
        Ok(())
    });
    let failure = result.expect_err("full-device write cannot publish a journal entry");
    assert_eq!(failure.raw_os_error(), Some(28), "Linux ENOSPC");
    assert!(
        read_candidates(&owner, ROOT, claim.object_len, IROH_PREORDER_16K)
            .unwrap()
            .is_empty(),
        "failed data operation must not mint a checkpoint claim"
    );
    assert!(inspect_quiescent_partial_files(&owner, disk_limits()).is_ok());
    drop(owner);
    fs::remove_dir_all(root).unwrap();
}
