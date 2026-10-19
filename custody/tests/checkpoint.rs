//! STY-G2-04a: OS-locked, crash-fail-closed checkpoint **metadata** tests.
//! No test here treats a checkpoint claim as authenticated FsStore data.
use staya_custody_lab::{
    StoreLease,
    checkpoint::{
        CheckpointClaim, IROH_PREORDER_16K, MetadataBarrier, publish_candidate, read_candidates,
    },
};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const ROOT: [u8; 32] = [0x42; 32];
const SIZE: u64 = 1_048_593;

fn root(label: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!(
        "staya-g2-04a-{}-{label}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn claim(sequence: u64) -> CheckpointClaim {
    CheckpointClaim {
        sequence,
        content_root: ROOT,
        object_len: SIZE,
        bao_profile: IROH_PREORDER_16K,
        start: (sequence - 1) * 16_384,
        end: sequence * 16_384,
    }
}

fn name(sequence: u64) -> String {
    format!(".staya-cp-{sequence:016}.bin")
}

fn candidates(lease: &StoreLease) -> Vec<CheckpointClaim> {
    read_candidates(lease, ROOT, SIZE, IROH_PREORDER_16K).unwrap()
}

#[test]
fn two_immutable_generations_reopen_as_untrusted_candidates_only() {
    let path = root("reopen");
    let lease = StoreLease::acquire(&path).unwrap();
    assert!(candidates(&lease).is_empty());
    let barrier = publish_candidate(&lease, claim(1)).unwrap();
    #[cfg(unix)]
    assert_eq!(barrier, MetadataBarrier::FileAndDirectorySynced);
    #[cfg(windows)]
    assert_eq!(barrier, MetadataBarrier::FileSyncedDirectoryUnproven);
    assert_eq!(candidates(&lease), vec![claim(1)]);
    publish_candidate(&lease, claim(2)).unwrap();
    assert_eq!(candidates(&lease), vec![claim(1), claim(2)]);
    drop(lease);

    // A *new OS process* acquires custody and parses the same journal. Even
    // there it obtains candidates only, not verified bytes or File Gate rights.
    let output = Command::new(env!("CARGO_BIN_EXE_staya-custody-worker"))
        .arg("checkpoint-read")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "independent checkpoint reader: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "ACQUIRED\nCANDIDATES=2"
    );
    let lease = StoreLease::acquire(&path).unwrap();
    assert_eq!(candidates(&lease).len(), 2);
    drop(lease);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn torn_or_tampered_record_refuses_reopen() {
    let path = root("torn");
    let lease = StoreLease::acquire(&path).unwrap();
    publish_candidate(&lease, claim(1)).unwrap();
    drop(lease);
    let record = path.join(name(1));
    let good = fs::read(&record).unwrap();
    let mut altered = good.clone();
    altered[62] ^= 1;
    fs::write(&record, &altered).unwrap();
    let reopened = StoreLease::acquire(&path).unwrap();
    assert!(read_candidates(&reopened, ROOT, SIZE, IROH_PREORDER_16K).is_err());
    drop(reopened);
    fs::write(&record, &good[..good.len() - 1]).unwrap();
    let reopened = StoreLease::acquire(&path).unwrap();
    assert!(read_candidates(&reopened, ROOT, SIZE, IROH_PREORDER_16K).is_err());
    drop(reopened);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn wrong_manifest_or_encoding_profile_refuses_reuse() {
    let path = root("identity");
    let lease = StoreLease::acquire(&path).unwrap();
    publish_candidate(&lease, claim(1)).unwrap();
    assert!(read_candidates(&lease, [7; 32], SIZE, IROH_PREORDER_16K).is_err());
    assert!(read_candidates(&lease, ROOT, SIZE + 1, IROH_PREORDER_16K).is_err());
    assert!(read_candidates(&lease, ROOT, SIZE, 77).is_err());
    drop(lease);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn malformed_filename_and_missing_generation_fail_closed() {
    let path = root("gap");
    let lease = StoreLease::acquire(&path).unwrap();
    publish_candidate(&lease, claim(1)).unwrap();
    publish_candidate(&lease, claim(2)).unwrap();
    fs::remove_file(path.join(name(1))).unwrap();
    assert!(read_candidates(&lease, ROOT, SIZE, IROH_PREORDER_16K).is_err());
    drop(lease);
    fs::remove_file(path.join(name(2))).unwrap();
    fs::write(path.join(".staya-cp-surprise.bin"), b"invalid").unwrap();
    let lease = StoreLease::acquire(&path).unwrap();
    assert!(read_candidates(&lease, ROOT, SIZE, IROH_PREORDER_16K).is_err());
    drop(lease);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn interrupted_temp_is_ignored_and_cannot_authorize_skip() {
    let path = root("tmp");
    let lease = StoreLease::acquire(&path).unwrap();
    fs::write(path.join(".staya-cp-tmp-0001-partial"), b"torn").unwrap();
    assert!(candidates(&lease).is_empty());
    publish_candidate(&lease, claim(1)).unwrap();
    assert_eq!(candidates(&lease), vec![claim(1)]);
    drop(lease);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn replay_unaligned_and_overquota_claims_are_refused_without_disk_write() {
    let path = root("reject");
    let lease = StoreLease::acquire(&path).unwrap();
    let mut unaligned = claim(1);
    unaligned.start = 1;
    assert!(publish_candidate(&lease, unaligned).is_err());
    let mut unknown = claim(1);
    unknown.bao_profile = 77;
    assert!(publish_candidate(&lease, unknown).is_err());
    let mut overquota = claim(129);
    overquota.start = 0;
    overquota.end = 16_384;
    assert!(publish_candidate(&lease, overquota).is_err());
    assert!(candidates(&lease).is_empty());

    publish_candidate(&lease, claim(1)).unwrap();
    assert!(publish_candidate(&lease, claim(1)).is_err());
    assert!(publish_candidate(&lease, claim(3)).is_err());
    assert_eq!(candidates(&lease), vec![claim(1)]);
    drop(lease);
    fs::remove_dir_all(path).unwrap();
}

#[cfg(unix)]
#[test]
fn published_symlink_is_not_trusted_as_checkpoint() {
    use std::os::unix::fs::symlink;
    let path = root("symlink");
    let lease = StoreLease::acquire(&path).unwrap();
    publish_candidate(&lease, claim(1)).unwrap();
    drop(lease);
    let original = path.join(name(1));
    let renamed = path.join("saved-real-record");
    fs::rename(&original, &renamed).unwrap();
    symlink(&renamed, &original).unwrap();
    let lease = StoreLease::acquire(&path).unwrap();
    assert!(read_candidates(&lease, ROOT, SIZE, IROH_PREORDER_16K).is_err());
    drop(lease);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn no_claim_may_be_added_when_store_ownership_is_lost() {
    let path = root("fence");
    let lease = StoreLease::acquire(&path).unwrap();
    let record = path.join(".staya-writer.lock");
    let moved = path.join("old-lock");
    if fs::rename(&record, &moved).is_ok() {
        fs::write(&record, b"replacement").unwrap();
        assert!(publish_candidate(&lease, claim(1)).is_err());
        assert!(!path.join(name(1)).exists());
    } else {
        // On Windows an open lock may itself stop a pathname replacement.
        lease.validate_fence().unwrap();
    }
    drop(lease);
    fs::remove_dir_all(path).unwrap();
}
