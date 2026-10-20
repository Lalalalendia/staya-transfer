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
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
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

#[test]
fn cleanup_unpublished_pending_names_only_and_requires_uncontested_owner() {
    let path = root("orphan-clean");
    let lease = StoreLease::acquire(&path).unwrap();
    publish_candidate(&lease, claim(1)).unwrap();
    let temp_a = path.join(".staya-cp-tmp-0001-partial");
    let temp_b = path.join(".staya-cp-tmp-0002-partial");
    fs::write(&temp_a, b"torn").unwrap();
    fs::write(&temp_b, b"").unwrap();
    fs::write(path.join("do-not-remove.txt"), b"ordinary file").unwrap();
    assert_eq!(candidates(&lease), vec![claim(1)]);
    let refused = Command::new(env!("CARGO_BIN_EXE_staya-custody-worker"))
        .arg("probe")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&refused.stdout).trim(), "BUSY");
    let cleaned = staya_custody_lab::checkpoint::cleanup_pending_records(&lease).unwrap();
    assert_eq!(cleaned.removed, 2);
    assert_eq!(cleaned.bytes, 4);
    assert!(!temp_a.exists() && !temp_b.exists());
    assert_eq!(
        fs::read(path.join("do-not-remove.txt")).unwrap(),
        b"ordinary file"
    );
    assert_eq!(candidates(&lease), vec![claim(1)]);
    drop(lease);
    let reopened = StoreLease::acquire(&path).unwrap();
    assert_eq!(candidates(&reopened), vec![claim(1)]);
    assert_eq!(
        staya_custody_lab::checkpoint::cleanup_pending_records(&reopened)
            .unwrap()
            .removed,
        0
    );
    drop(reopened);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn oversized_unpublished_temp_fails_closed_without_removing_anything() {
    let path = root("orphan-size");
    let lease = StoreLease::acquire(&path).unwrap();
    let oversized = path.join(".staya-cp-tmp-oversized");
    fs::write(&oversized, vec![0x7d; 109]).unwrap();
    assert!(read_candidates(&lease, ROOT, SIZE, IROH_PREORDER_16K).is_err());
    assert!(publish_candidate(&lease, claim(1)).is_err());
    assert!(staya_custody_lab::checkpoint::cleanup_pending_records(&lease).is_err());
    assert_eq!(fs::metadata(&oversized).unwrap().len(), 109);
    assert!(!path.join(name(1)).exists());
    fs::remove_file(oversized).unwrap();
    publish_candidate(&lease, claim(1)).unwrap();
    drop(lease);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn pending_count_limit_denies_all_checkpoint_publication() {
    use staya_custody_lab::checkpoint::MAX_PENDING_CLAIMS;
    let path = root("orphan-count");
    let lease = StoreLease::acquire(&path).unwrap();
    for n in 0..=MAX_PENDING_CLAIMS {
        fs::write(path.join(format!(".staya-cp-tmp-{n:04}")), b"").unwrap();
    }
    assert!(read_candidates(&lease, ROOT, SIZE, IROH_PREORDER_16K).is_err());
    assert!(publish_candidate(&lease, claim(1)).is_err());
    assert!(staya_custody_lab::checkpoint::cleanup_pending_records(&lease).is_err());
    assert!(!path.join(name(1)).exists());
    fs::remove_file(path.join(format!(".staya-cp-tmp-{MAX_PENDING_CLAIMS:04}"))).unwrap();
    let cleaned = staya_custody_lab::checkpoint::cleanup_pending_records(&lease).unwrap();
    assert_eq!(cleaned.removed, MAX_PENDING_CLAIMS);
    publish_candidate(&lease, claim(1)).unwrap();
    drop(lease);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn root_directory_scan_quota_is_bounded_even_for_unrelated_files() {
    use staya_custody_lab::checkpoint::MAX_ROOT_ENTRIES;
    let path = root("orphan-scan");
    let lease = StoreLease::acquire(&path).unwrap();
    for n in 0..MAX_ROOT_ENTRIES {
        fs::write(path.join(format!("unrelated-{n:04}.tmp")), b"").unwrap();
    }
    assert!(read_candidates(&lease, ROOT, SIZE, IROH_PREORDER_16K).is_err());
    assert!(staya_custody_lab::checkpoint::cleanup_pending_records(&lease).is_err());
    assert!(!path.join(name(1)).exists());
    drop(lease);
    fs::remove_dir_all(path).unwrap();
}

#[cfg(unix)]
#[test]
fn pending_symlink_is_never_ignored_or_deleted() {
    use std::os::unix::fs::symlink;
    let path = root("orphan-symlink");
    let lease = StoreLease::acquire(&path).unwrap();
    fs::write(path.join("untouched"), b"important").unwrap();
    symlink(path.join("untouched"), path.join(".staya-cp-tmp-evil")).unwrap();
    assert!(read_candidates(&lease, ROOT, SIZE, IROH_PREORDER_16K).is_err());
    assert!(staya_custody_lab::checkpoint::cleanup_pending_records(&lease).is_err());
    assert_eq!(fs::read(path.join("untouched")).unwrap(), b"important");
    drop(lease);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn forged_checksum_cannot_change_locally_trusted_content_identity() {
    let path = root("forged-root");
    let owner = StoreLease::acquire(&path).unwrap();
    publish_candidate(&owner, claim(1)).unwrap();
    let journal = path.join(name(1));
    let mut bytes = fs::read(&journal).unwrap();
    // This is NOT a keyed MAC: an attacker can recompute it. The independent
    // locally trusted root still must reject such a syntactically valid record.
    bytes[16] ^= 0x40;
    let digest = blake3::hash(&bytes[..76]);
    bytes[76..].copy_from_slice(digest.as_bytes());
    fs::write(&journal, bytes).unwrap();
    assert!(read_candidates(&owner, ROOT, SIZE, IROH_PREORDER_16K).is_err());
    assert!(!path.join(name(2)).exists());
    drop(owner);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn replayed_valid_metadata_is_only_untrusted_candidate_not_proof() {
    let source = root("replay-source");
    let owner = StoreLease::acquire(&source).unwrap();
    publish_candidate(&owner, claim(1)).unwrap();
    let legitimate_record = fs::read(source.join(name(1))).unwrap();
    drop(owner);

    let foreign = root("replay-foreign");
    fs::write(foreign.join(name(1)), legitimate_record).unwrap();
    let separate_owner = StoreLease::acquire(&foreign).unwrap();
    // Journal parsing alone cannot establish the existence of physical
    // FsStore data/outboard or grant verified-range/skip capability.
    assert_eq!(
        read_candidates(&separate_owner, ROOT, SIZE, IROH_PREORDER_16K).unwrap(),
        vec![claim(1)]
    );
    // Local root and size fencing must still reject cross-object reuse.
    assert!(read_candidates(&separate_owner, [9; 32], SIZE, IROH_PREORDER_16K).is_err());
    assert!(read_candidates(&separate_owner, ROOT, SIZE + 1, IROH_PREORDER_16K).is_err());
    drop(separate_owner);
    fs::remove_dir_all(foreign).unwrap();
    fs::remove_dir_all(source).unwrap();
}
