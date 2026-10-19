//! STY-G2-02: actual pinned FsStore partial import -> clean shutdown -> reopen.
//!
//! This deliberately does NOT claim SIGKILL survival or a persistent checkpoint.
//! All files are disposable private CI fixtures, never Akula user documents.

#[path = "fsstore_partial_adapter.rs"]
mod partial_adapter;

use bao_tree::{
    BlockSize, ByteRanges,
    io::{outboard::PreOrderMemOutboard, round_up_to_chunks, sync::encode_ranges_validated},
};
use iroh_blobs::{Hash, api::blobs::BlobStatus, store::fs::FsStore};
use partial_adapter::{
    audit_clean_closed_fixture, stage_verified_fixture, stage_with_inflight_budget,
};
use staya_custody_lab::{
    StoreLease,
    admission::{Limits, SharedAdmission},
    checkpoint::{CheckpointClaim, IROH_PREORDER_16K, read_candidates},
    partial_barrier::publish_after_quiescent_audit,
};
use staya_transfer::{
    ByteRange, ContentId, Manifest,
    recovery::{BaoStorageProfile, StoreIdentity},
};
use std::{
    fs,
    io::{self, Seek, SeekFrom, Write},
    sync::atomic::AtomicBool,
    time::Duration,
};

const LEN: usize = 8 * 1024 * 1024 + 17;
const START: u64 = 32_768;
const END: u64 = 196_608;
const TIMEOUT: Duration = Duration::from_secs(90);
const BLOCK: BlockSize = BlockSize::from_chunk_log(4);

fn make_data() -> Vec<u8> {
    (0..LEN).map(|i| ((i * 37 + 11) % 251) as u8).collect()
}

fn prepare(data: &[u8]) -> (StoreIdentity, Vec<u8>) {
    let outboard = PreOrderMemOutboard::create(data, BLOCK);
    let root = *outboard.root.as_bytes();
    assert_eq!(root, *blake3::hash(data).as_bytes());
    let mut bao = Vec::new();
    let requested = round_up_to_chunks(&ByteRanges::from(START..END));
    encode_ranges_validated(data, &outboard, &requested, &mut bao)
        .expect("create trusted Bao fixture");
    let mut wire = (data.len() as u64).to_le_bytes().to_vec();
    wire.extend_from_slice(&bao);
    (
        StoreIdentity {
            manifest: Manifest {
                id: ContentId(root),
                size: data.len() as u64,
            },
            profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
        },
        wire,
    )
}

fn range() -> ByteRange {
    ByteRange::new(START, END, LEN as u64).expect("bounded nonempty interval")
}

#[tokio::test(flavor = "multi_thread")]
async fn pinned_partial_import_clean_reopen_with_physical_bao_audit() {
    tokio::time::timeout(TIMEOUT, async {
        let root = std::env::temp_dir().join(format!(
            "staya-g2-02-{}-{}",
            std::process::id(),
            std::env::var("STY_INTEROP_VARIANT").unwrap_or_else(|_| "ci".to_owned()),
        ));
        assert!(!root.exists(), "do not reuse an existing directory");
        fs::create_dir(&root).expect("new private fixture");
        // Acquire OS writer custody BEFORE loading the pinned FsStore actor.
        let ownership = StoreLease::acquire(&root).expect("private store owner");
        let payload = make_data();
        let (identity, wire) = prepare(&payload);
        let hash = Hash::from_bytes(identity.manifest.id.0);
        let store = FsStore::load(&root).await.expect("real pinned FsStore");

        // Reject even *cryptographically valid* subrange requests that do not
        // form complete Bao storage groups: they cannot yet be checkpointed.
        let unaligned = ByteRange::new(33_333, 200_111, LEN as u64).unwrap();
        assert!(stage_verified_fixture(&store, identity, unaligned, &wire).await.is_err());

        // Invalid caller profile/length/root/proof must fail BEFORE any FsStore import.
        let mut wrong_profile = identity;
        wrong_profile.profile = BaoStorageProfile::Unsupported(1234);
        assert!(stage_verified_fixture(&store, wrong_profile, range(), &wire).await.is_err());

        let mut wrong_len = identity;
        wrong_len.manifest.size += 1;
        assert!(stage_verified_fixture(&store, wrong_len, range(), &wire).await.is_err());

        let mut wrong_root = identity;
        wrong_root.manifest.id.0[0] ^= 1;
        assert!(stage_verified_fixture(&store, wrong_root, range(), &wire).await.is_err());

        let mut corrupt = wire.clone();
        let middle = corrupt.len() / 2;
        corrupt[middle] ^= 0x40;
        assert!(stage_verified_fixture(&store, identity, range(), &corrupt).await.is_err());

        let mut truncated = wire.clone();
        truncated.pop();
        assert!(stage_verified_fixture(&store, identity, range(), &truncated).await.is_err());

        let mut trailing = wire.clone();
        trailing.push(0xCA);
        assert!(stage_verified_fixture(&store, identity, range(), &trailing).await.is_err());

        assert!(
            matches!(store.blobs().status(hash).await.expect("unchanged store"), BlobStatus::NotFound),
            "negative cases must not create partial metadata"
        );

        // Actual pinned FsStore import of a verified partial Bao object.
        stage_verified_fixture(&store, identity, range(), &wire)
            .await
            .expect("real staged Bao import");
        assert!(
            !matches!(store.blobs().status(hash).await.expect("partial status"), BlobStatus::Complete { .. }),
            "single interval must not mark an 8 MiB object complete"
        );
        let before = store.blobs().observe(hash).await.expect("observe partial before close");
        assert!(!before.is_complete(), "object must remain partial");
        assert!(before.total_bytes() > 0, "first verified range was staged");

        store.shutdown().await.expect("clean store shutdown, not crash durability");
        drop(store);

        // Independently validate real physical data and real outboard from disk.
        let data_path = root.join("data").join(format!("{}.data", hash.to_hex()));
        let proof_path = root.join("data").join(format!("{}.obao4", hash.to_hex()));
        let data_bytes = fs::metadata(&data_path).map(|x| x.len()).unwrap_or(0);
        let proof_bytes = fs::metadata(&proof_path).map(|x| x.len()).unwrap_or(0);
        println!(
            "STY_G2_02_PHYSICAL_BEFORE_REOPEN data_len={data_bytes} outboard_len={proof_bytes} expected_size={LEN}"
        );
        let physical = audit_clean_closed_fixture(&root, identity, range())
            .expect("post-shutdown physically stored Bao must match root");
        assert_eq!(physical, payload[START as usize..END as usize]);

        // Real FsStore + independent physical Bao audit + four backing file
        // sync barriers under a single cooperative owner. A checkpoint is
        // still only a candidate, never a durable/APPLIED byte-range receipt.
        let journal_claim = CheckpointClaim {
            sequence: 1,
            content_root: identity.manifest.id.0,
            object_len: identity.manifest.size,
            bao_profile: IROH_PREORDER_16K,
            start: START,
            end: END,
        };
        assert!(
            publish_after_quiescent_audit(&ownership, journal_claim, |_| {
                Err(io::Error::other("mandatory negative audit denied"))
            })
            .is_err()
        );
        assert!(
            read_candidates(
                &ownership,
                identity.manifest.id.0,
                identity.manifest.size,
                IROH_PREORDER_16K
            )
            .unwrap()
            .is_empty()
        );
        publish_after_quiescent_audit(&ownership, journal_claim, |_| {
            let actual = audit_clean_closed_fixture(&root, identity, range())
                .map_err(io::Error::other)?;
            if actual != payload[START as usize..END as usize] {
                return Err(io::Error::other("independent Bao physical bytes differ"));
            }
            Ok(())
        })
        .expect("quiescent FsStore physical Bao plus directory barrier");
        assert_eq!(
            read_candidates(
                &ownership,
                identity.manifest.id.0,
                identity.manifest.size,
                IROH_PREORDER_16K
            )
            .unwrap(),
            vec![journal_claim]
        );
        println!(
            "STY_G2_04B real_fsstore=true backing_sync=true independent_bao_audit=true checkpoint_claim=true durable_after_sigkill=false file_gate=false"
        );

        let reopened = FsStore::load(&root).await.expect("reopen separate store instance");
        let after = reopened.blobs().observe(hash).await.expect("read reopened bitfield");
        assert!(!after.is_complete(), "still partial after restart");
        assert!(after.total_bytes() > 0, "some ranges were retained after clean shutdown");
        // A bitfield on its own is not independent proof; do not authorize
        // skipping its ranges until the physical readback was authenticated.
        reopened.shutdown().await.expect("close reopened actor");
        drop(reopened);

        // Corrupt the data file only AFTER FsStore is closed. Audit must fail.
        let data_path = root.join("data").join(format!("{}.data", hash.to_hex()));
        let mut owned = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&data_path)
            .expect("test-only private data");
        owned.seek(SeekFrom::Start(START)).unwrap();
        owned.write_all(&[payload[START as usize] ^ 0x80]).unwrap();
        owned.sync_all().unwrap();
        drop(owned);
        assert!(
            audit_clean_closed_fixture(&root, identity, range()).is_err(),
            "modified stored data must not become a trusted range"
        );
        // Even a valid persisted journal entry MUST NOT let the planner skip
        // corrupted physical bytes. The claim remains deliberately untrusted.
        assert_eq!(
            read_candidates(
                &ownership,
                identity.manifest.id.0,
                identity.manifest.size,
                IROH_PREORDER_16K
            )
            .unwrap(),
            vec![journal_claim]
        );

        // Restore the fixture and then remove the proof entirely to isolate
        // that second negative case (not merely a stale corrupted data failure).
        let mut owned = fs::OpenOptions::new().write(true).open(&data_path).unwrap();
        owned.seek(SeekFrom::Start(START)).unwrap();
        owned.write_all(&[payload[START as usize]]).unwrap();
        owned.sync_all().unwrap();
        drop(owned);
        assert!(audit_clean_closed_fixture(&root, identity, range()).is_ok());
        let proof_path = root.join("data").join(format!("{}.obao4", hash.to_hex()));
        fs::remove_file(&proof_path).expect("destroy disposable proof");
        assert!(
            audit_clean_closed_fixture(&root, identity, range()).is_err(),
            "missing Bao outboard cannot mint verified range"
        );

        drop(ownership);
        fs::remove_dir_all(&root).expect("remove private fixture only");
        println!(
            "STY_G2_02 real_fsstore=true partial_bao_import=true clean_reopen=true physical_audit=true tamper_hold=true missing_outboard_hold=true crash_durable=false single_writer=false file_gate=false"
        );
    })
    .await
    .expect("bounded G2-02 partial-store fixture");
}

#[tokio::test(flavor = "multi_thread")]
async fn real_fsstore_admission_rejects_before_write_and_releases_after_stage() {
    tokio::time::timeout(TIMEOUT, async {
        let root = std::env::temp_dir().join(format!(
            "staya-g2-05f-{}-{}",
            std::process::id(),
            std::env::var("STY_INTEROP_VARIANT").unwrap_or_else(|_| "ci".to_owned()),
        ));
        assert!(!root.exists(), "fresh disposable directory only");
        fs::create_dir(&root).expect("new private test store");
        let owner = StoreLease::acquire(&root).expect("single cooperative owner");
        let payload = make_data();
        let (identity, wire) = prepare(&payload);
        let hash = Hash::from_bytes(identity.manifest.id.0);
        let store = FsStore::load(&root).await.expect("pinned real FsStore");

        let required = range()
            .len()
            .checked_add(u64::try_from(wire.len()).unwrap())
            .unwrap();
        let small = SharedAdmission::new(Limits {
            max_partial_objects: 1,
            max_reserved_bytes: required - 1,
            max_open_handles: 4,
            max_retries_per_object: 2,
        })
        .unwrap();
        let budget = SharedAdmission::new(Limits {
            max_partial_objects: 1,
            max_reserved_bytes: required,
            max_open_handles: 4,
            max_retries_per_object: 2,
        })
        .unwrap();
        let cancelled = AtomicBool::new(false);
        assert!(
            stage_with_inflight_budget(
                &owner, &small, &store, identity, range(), &wire, &cancelled,
            )
            .await
            .is_err(),
            "one byte below the conservative logical budget must refuse before IO"
        );
        assert_eq!(small.usage().unwrap(), (0, 0, 0));
        assert!(
            matches!(
                store.blobs().status(hash).await.unwrap(),
                BlobStatus::NotFound
            ),
            "budget denial must not create FsStore partial metadata"
        );

        cancelled.store(true, std::sync::atomic::Ordering::Release);
        assert!(
            stage_with_inflight_budget(
                &owner, &budget, &store, identity, range(), &wire, &cancelled,
            )
            .await
            .is_err()
        );
        assert_eq!(budget.usage().unwrap(), (0, 0, 0));
        cancelled.store(false, std::sync::atomic::Ordering::Release);

        let mut invalid_wire = wire.clone();
        let middle = invalid_wire.len() / 2;
        invalid_wire[middle] ^= 0x40;
        assert!(
            stage_with_inflight_budget(
                &owner, &budget, &store, identity, range(), &invalid_wire, &cancelled,
            )
            .await
            .is_err(),
            "invalid Bao proof may not bypass budget or mutate actor"
        );
        assert_eq!(budget.usage().unwrap(), (0, 0, 0));
        assert!(matches!(
            store.blobs().status(hash).await.unwrap(),
            BlobStatus::NotFound
        ));

        let (_accepted, permit) = stage_with_inflight_budget(
            &owner, &budget, &store, identity, range(), &wire, &cancelled,
        )
        .await
        .expect("real verified partial Bao admitted");
        assert_eq!(budget.usage().unwrap(), (1, required, 4));
        assert!(
            stage_with_inflight_budget(
                &owner, &budget, &store, identity, range(), &wire, &cancelled,
            )
            .await
            .is_err(),
            "second pending import must be refused while permit is alive"
        );
        assert_eq!(budget.usage().unwrap(), (1, required, 4));
        budget.stop_admissions().expect("one-way closing barrier");
        assert!(
            !budget.admissions_drained().unwrap(),
            "closing may not forget the active import permit"
        );
        drop(permit);
        assert!(budget.admissions_drained().unwrap());
        assert_eq!(budget.usage().unwrap(), (0, 0, 0));
        assert!(
            stage_with_inflight_budget(
                &owner, &budget, &store, identity, range(), &wire, &cancelled,
            )
            .await
            .is_err(),
            "a drained but closing ledger must not admit another real FsStore import"
        );
        // Admission drained != actor stopped: only the actual shutdown below
        // can establish the separate clean FsStore quiescence prerequisite.
        store.shutdown().await.expect("clean shutdown is NOT SIGKILL");
        drop(store);

        let audited = audit_clean_closed_fixture(&root, identity, range())
            .expect("independent physical Bao readback");
        assert_eq!(audited, payload[START as usize..END as usize]);
        assert!(
            read_candidates(
                &owner, identity.manifest.id.0, identity.manifest.size,
                IROH_PREORDER_16K,
            )
            .unwrap()
            .is_empty(),
            "uncommitted actor acceptance never creates a checkpoint claim"
        );
        drop(owner);
        fs::remove_dir_all(root).expect("remove only test directory");
        println!(
            "STY_G2_05F real_fsstore=true admission_before_write=true cancel_preimport=true bounded_bao_proof=true concurrent_limit=true physical_audit=true durable_ack=false actual_disk_quota=false file_gate=false closing_gate=true permit_drained=true actor_shutdown_separate=true"
        );
    })
    .await
    .expect("bounded G2-05f real FsStore fixture");
}


#[tokio::test(flavor = "multi_thread")]
async fn clean_reopen_authenticated_range_controls_missing_inventory() {
    use staya_transfer::{
        TransferBudget, TransferRequest,
        bao::verify_bao_range,
        planner::{MissingRanges, VerifiedCheckpoint},
    };
    tokio::time::timeout(TIMEOUT, async {
        if let Some(root) = std::env::var_os("STY_G2_06A_COLD_AUDIT_ROOT") {
            let root = std::path::PathBuf::from(root);
            let lease = StoreLease::acquire(&root)
                .expect("cold OS process must independently own store");
            let source = make_data();
            let (trusted, _) = prepare(&source);
            let physical = audit_clean_closed_fixture(&root, trusted, range())
                .expect("independent process reads and Bao-authenticates physical sidecars");
            assert_eq!(physical, source[START as usize..END as usize]);
            drop(lease);
            println!(
                "STY_G2_06A_COLD_AUDIT independent_process=true physical_bao=true checkpoint_trusted=false"
            );
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "staya-g2-06a-{}-{}",
            std::process::id(),
            std::env::var("STY_INTEROP_VARIANT").unwrap_or_else(|_| "ci".to_owned())
        ));
        assert!(!dir.exists());
        fs::create_dir(&dir).unwrap();
        let lease = StoreLease::acquire(&dir).unwrap();
        let data = make_data();
        let (identity, proof) = prepare(&data);
        let store = FsStore::load(&dir).await.unwrap();
        stage_verified_fixture(&store, identity, range(), &proof).await.unwrap();
        store.shutdown().await.unwrap();
        drop(store);
        // Prove cold readback by a separate OS process, not merely a second
        // function call using in-memory FsStore handles. The child acquires
        // exclusive custody and audits the physical .data/.obao4 files.
        drop(lease);
        let cold = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("clean_reopen_authenticated_range_controls_missing_inventory")
            .arg("--nocapture")
            .env("STY_G2_06A_COLD_AUDIT_ROOT", &dir)
            .output()
            .expect("start independent cold-reopen verifier");
        let cold_stdout = String::from_utf8_lossy(&cold.stdout);
        assert!(
            cold.status.success() && cold_stdout.contains("STY_G2_06A_COLD_AUDIT"),
            "cold audit process failed: stdout={cold_stdout} stderr={}",
            String::from_utf8_lossy(&cold.stderr)
        );
        let lease = StoreLease::acquire(&dir)
            .expect("parent reacquires after independent verifier exits");
        let physical = audit_clean_closed_fixture(&dir, identity, range()).unwrap();
        assert_eq!(physical, data[START as usize..END as usize]);

        let trusted_manifest = identity.manifest;
        let request = TransferRequest::new(trusted_manifest, range()).unwrap();
        let validated = verify_bao_range(&request, &proof[8..]).unwrap();
        assert_eq!(validated.bytes(), physical.as_slice());
        let mut confirmed = VerifiedCheckpoint::empty(trusted_manifest);
        confirmed.record_bao(validated).unwrap();
        let budget = TransferBudget {
            max_inflight_bytes: 1024 * 1024,
            max_sources: 1,
            max_retries: 0,
        };
        let wanted: Vec<_> = MissingRanges::from_checkpoint(trusted_manifest, &confirmed, budget)
            .unwrap()
            .map(|r| (r.start(), r.end()))
            .collect();
        assert_eq!(wanted.first().copied(), Some((0, START)));
        assert!(wanted.iter().all(|&(a, b)| b <= START || a >= END));
        assert_eq!(wanted.iter().map(|(a, b)| b - a).sum::<u64>(),
                   trusted_manifest.size - (END - START));

        let data_path = dir
            .join("data")
            .join(format!("{}.data", Hash::from_bytes(identity.manifest.id.0).to_hex()));
        let mut file = fs::OpenOptions::new().write(true).open(data_path).unwrap();
        file.seek(SeekFrom::Start(START)).unwrap();
        file.write_all(&[data[START as usize] ^ 0x80]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(audit_clean_closed_fixture(&dir, identity, range()).is_err());
        // Failed physical audit must yield an EMPTY inventory, never a skip.
        let empty = VerifiedCheckpoint::empty(trusted_manifest);
        let full: u64 = MissingRanges::from_checkpoint(trusted_manifest, &empty, budget)
            .unwrap()
            .map(|r| r.len())
            .sum();
        assert_eq!(full, trusted_manifest.size);
        drop(lease);
        fs::remove_dir_all(dir).unwrap();
        println!(
            "STY_G2_06A clean_shutdown=true cold_process=true physical_bao=true safe_missing_inventory=true corrupted_storage_full_retry=true crash_resume=false network_get=false file_gate=false"
        );
    })
    .await
    .expect("bounded G2-06a clean-reopen inventory test");
}
