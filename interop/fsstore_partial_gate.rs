//! STY-G2-02: actual pinned FsStore partial import -> clean shutdown -> reopen.
//!
//! This deliberately does NOT claim SIGKILL survival or a persistent checkpoint.
//! All files are disposable private CI fixtures, never Akula user documents.

#[path = "fsstore_partial_adapter.rs"]
mod partial_adapter;

#[path = "fsstore_shutdown_supervisor.rs"]
mod shutdown_supervisor;

use bao_tree::{
    BlockSize, ByteRanges,
    io::{outboard::PreOrderMemOutboard, round_up_to_chunks, sync::encode_ranges_validated},
};
use iroh_blobs::{Hash, api::blobs::BlobStatus, store::fs::FsStore};
use partial_adapter::{
    audit_clean_closed_fixture, stage_verified_fixture, stage_with_inflight_budget,
};
use shutdown_supervisor::ActiveFsStore;
use staya_custody_lab::{
    StoreLease,
    admission::{Limits, Reservation, SharedAdmission},
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
async fn real_fsstore_supervised_quiescence_blocks_early_handoff_and_reaudits_bao() {
    tokio::time::timeout(TIMEOUT, async {
        let root = std::env::temp_dir().join(format!(
            "staya-g2-05h2-{}-{}",
            std::process::id(),
            std::env::var("STY_INTEROP_VARIANT").unwrap_or_else(|_| "ci".to_owned()),
        ));
        assert!(!root.exists(), "no existing user store may be reused");
        fs::create_dir(&root).expect("new private test root");
        let payload = make_data();
        let (expected, wire) = prepare(&payload);
        let reserved_bytes = range()
            .len()
            .checked_add(u64::try_from(wire.len()).unwrap())
            .unwrap();
        let active = ActiveFsStore::open(
            &root,
            Limits {
                max_partial_objects: 1,
                max_reserved_bytes: reserved_bytes,
                max_open_handles: 4,
                max_retries_per_object: 2,
            },
        )
        .await
        .expect("real actor must start under its OS owner");

        let cancelled = AtomicBool::new(false);
        let (_accepted, held_permit) = active
            .stage(expected, range(), &wire, &cancelled)
            .await
            .expect("real Bao import accepted under a live permit");
        let closing = active
            .begin_closing()
            .unwrap_or_else(|(_, e)| panic!("cannot begin real actor closure: {e}"));
        assert!(
            closing
                .admissions()
                .reserve(Reservation::new(1, 1, 1).unwrap())
                .is_err(),
            "no permits from late clones after Closing begins"
        );

        // Actor shutdown is denied, and the original OS lease remains
        // owned, while one real imported range still has an active permit.
        let closing = match closing.finish().await {
            Ok(_) => panic!("a live permit may not become quiescent"),
            Err((closing, error)) => {
                assert!(error.contains("permits have not drained"), "{error}");
                closing
            }
        };
        assert!(
            matches!(
                StoreLease::acquire(&root),
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock
            ),
            "failed quiescence may not permit a second cooperative OS writer"
        );

        drop(held_permit);
        assert!(closing.admissions().admissions_drained().unwrap());
        // Only the *actual* pinned FsStore actor's successful shutdown can
        // construct the private quiescence witness. No caller can mint it.
        let quiescent = match closing.finish().await {
            Ok(result) => result,
            Err((_, err)) => panic!("real FsStore actor shutdown failed: {err}"),
        };
        assert!(quiescent.admissions_drained().unwrap());
        assert!(
            matches!(
                StoreLease::acquire(&root),
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock
            ),
            "quiescent witness must still hold OS custody for Bao audit"
        );
        let physical = audit_clean_closed_fixture(&root, expected, range())
            .expect("independently authenticate the physical sparse Bao range");
        assert_eq!(physical, payload[START as usize..END as usize]);
        assert!(
            read_candidates(
                quiescent.owner(),
                expected.manifest.id.0,
                expected.manifest.size,
                IROH_PREORDER_16K,
            )
            .unwrap()
            .is_empty(),
            "successfully closing an actor must not publish a checkpoint"
        );
        quiescent.finish_clean(); // drops the lock; NEVER calls explicit LOCK_UN.

        let second = StoreLease::acquire(&root)
            .expect("another cooperative writer can acquire after clean closure");
        let reopened = FsStore::load(&root)
            .await
            .expect("real actor reopens while the second owner is held");
        let authenticated = audit_clean_closed_fixture(&root, expected, range())
            .expect("reopened owner independently rechecks the same bytes");
        assert_eq!(authenticated, payload[START as usize..END as usize]);
        reopened
            .shutdown()
            .await
            .expect("second actor must shut down cleanly");
        drop(reopened);
        drop(second);
        fs::remove_dir_all(&root).expect("remove only disposable test root");
        println!(
            "STY_G2_05H2 real_fsstore=true owner_held_during_drain=true close_denied_with_permit=true actor_shutdown_confirmed=true quiescent_witness_private=true physical_bao_reverified=true checkpoint_minted=false explicit_lock_un=false child_writer_join_proven=false file_gate=false"
        );
    })
    .await
    .expect("bounded real FsStore actor shutdown fixture");
}

#[tokio::test(flavor = "multi_thread")]
async fn real_fsstore_abandoned_actor_drop_keeps_os_lock_until_process_exit() {
    // Test the fail-closed emergency path in a disposable INDEPENDENT
    // subprocess. Intentional custody leakage cannot contaminate unrelated
    // test cases, and process exit must release the leaked OS handle.
    const MARKER: &str = "STY_G2_05H2_ABANDONED_ACTOR_HOLD";
    const OPEN_MARKER: &str = "STY_G2_05H2_ABANDONED_OPEN_HOLD";
    if let Some(root) = std::env::var_os("STY_G2_05H2_OPEN_CHILD_ROOT") {
        let root = std::path::PathBuf::from(root);
        // Simulate cancellation after acquiring the opening lease. This
        // tests the opening guard's Drop, NOT a real interrupted actor load.
        shutdown_supervisor::simulate_cancelled_open_for_test(&root)
            .expect("cancelled opening lease must remain held");
        assert!(
            matches!(
                StoreLease::acquire(&root),
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock
            ),
            "cancelled opening may not admit another writer"
        );
        println!("{OPEN_MARKER} custody_retained=true");
        return;
    }
    if let Some(root) = std::env::var_os("STY_G2_05H2_ABANDON_CHILD_ROOT") {
        let root = std::path::PathBuf::from(root);
        let active = ActiveFsStore::open(
            &root,
            Limits {
                max_partial_objects: 1,
                max_reserved_bytes: 4096,
                max_open_handles: 4,
                max_retries_per_object: 1,
            },
        )
        .await
        .expect("child starts real FsStore under OS custody");
        // No successful actor shutdown has occurred. Dropping must HOLD the
        // original OS lease despite the actor object being abandoned.
        drop(active);
        assert!(
            matches!(
                StoreLease::acquire(&root),
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock
            ),
            "prematurely dropped active actor must not enable a new writer"
        );
        println!("{MARKER} custody_retained=true");
        return;
    }

    let root = std::env::temp_dir().join(format!(
        "staya-g2-05h2-abandon-parent-{}",
        std::process::id()
    ));
    assert!(!root.exists(), "only use a fresh private root");
    fs::create_dir(&root).expect("private test root");
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("real_fsstore_abandoned_actor_drop_keeps_os_lock_until_process_exit")
        .arg("--nocapture")
        .env("STY_G2_05H2_ABANDON_CHILD_ROOT", &root)
        .output()
        .expect("run OS-independent actor-abandon test child");
    let output = String::from_utf8_lossy(&result.stdout);
    assert!(
        result.status.success() && output.contains(MARKER),
        "abandoned-actor subprocess: stdout={output} stderr={}",
        String::from_utf8_lossy(&result.stderr)
    );
    // Killing/exiting the OS process ultimately closes its handles. No
    // journal claim, bytes reuse or filesystem durability is inferred.
    let owner = StoreLease::acquire(&root)
        .expect("a new process may reacquire after the abandoned process exits");
    drop(owner);
    let cancelled_open = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("real_fsstore_abandoned_actor_drop_keeps_os_lock_until_process_exit")
        .arg("--nocapture")
        .env("STY_G2_05H2_OPEN_CHILD_ROOT", &root)
        .output()
        .expect("run independent simulated opening-cancellation child");
    let open_output = String::from_utf8_lossy(&cancelled_open.stdout);
    assert!(
        cancelled_open.status.success() && open_output.contains(OPEN_MARKER),
        "cancelled opening subprocess: stdout={open_output} stderr={}",
        String::from_utf8_lossy(&cancelled_open.stderr)
    );
    let after_open = StoreLease::acquire(&root)
        .expect("OS process exit must release intentionally leaked opening custody");
    drop(after_open);
    fs::remove_dir_all(&root).expect("dispose private fixture");
    println!(
        "STY_G2_05H2_ABANDON_RECOVERY real_process=true lock_held_before_exit=true cancelled_opening_guard=true reacquire_after_exit=true durable_receipt=false"
    );
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
        let mut cold_child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("clean_reopen_authenticated_range_controls_missing_inventory")
            .arg("--nocapture")
            .env("STY_G2_06A_COLD_AUDIT_ROOT", &dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("start independent cold-reopen verifier");
        let started = std::time::Instant::now();
        loop {
            if cold_child
                .try_wait()
                .expect("cold auditor process status")
                .is_some()
            {
                break;
            }
            if started.elapsed() > Duration::from_secs(30) {
                let _ = cold_child.kill();
                let _ = cold_child.wait();
                panic!("cold Bao auditor exceeded bounded process deadline");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let cold = cold_child
            .wait_with_output()
            .expect("capture independent cold Bao auditor");
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

/// G2-05h3a: The parent holds only an OS child-process handle. The child
/// starts the *real* pinned FsStore under its own exclusive StoreLease AFTER
/// exec, so the launcher never holds a lock file description that fork may
/// inherit. A clean handoff requires actor shutdown + child-process join.
/// An abnormal termination requires kill + OS reap + independent new custody.
/// This is an isolated integration LAB, not a production IPC protocol.
#[tokio::test(flavor = "multi_thread")]
async fn real_fsstore_os_process_supervisor_clean_and_kill() {
    use std::{
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
        sync::mpsc,
        thread,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    const READY_MARKER: &str = "STY_G2_05H3A_CHILD_READY";
    const CLEAN_MARKER: &str = "STY_G2_05H3A_CHILD_CLEAN";

    // The identical test binary runs inside a dedicated OS process. All
    // actual FsStore actors and the OS lease live only in that process.
    if let Some(root) = std::env::var_os("STY_G2_05H3A_CHILD_ROOT") {
        let root = std::path::PathBuf::from(root);
        let payload = make_data();
        let (identity, wire) = prepare(&payload);
        let required = range()
            .len()
            .checked_add(u64::try_from(wire.len()).unwrap())
            .unwrap();
        let active = ActiveFsStore::open(
            &root,
            Limits {
                max_partial_objects: 1,
                max_reserved_bytes: required,
                max_open_handles: 4,
                max_retries_per_object: 2,
            },
        )
        .await
        .expect("only child owns the FsStore and exclusive OS lease");
        let cancel = AtomicBool::new(false);
        let (_receipt, permit) = active
            .stage(identity, range(), &wire, &cancel)
            .await
            .expect("child stages real authenticated Bao");
        drop(permit);
        println!("{READY_MARKER} actor_running=true lease_owned_by_child=true");
        io::stdout().flush().unwrap();

        // Do not close stdin in the parent until the clean/kill decision.
        // Blocking IO is isolated from Tokio's actor threads.
        let command = tokio::task::spawn_blocking(|| {
            let mut line = String::new();
            io::stdin()
                .lock()
                .read_line(&mut line)
                .expect("supervisor command input");
            line
        })
        .await
        .expect("stdin reader task");
        assert_eq!(
            command.trim(),
            "CLOSE",
            "only explicit clean close admitted"
        );
        let closing = active
            .begin_closing()
            .unwrap_or_else(|(_, e)| panic!("child cannot enter closing: {e}"));
        let quiescent = closing
            .finish()
            .await
            .unwrap_or_else(|(_, e)| panic!("actor shutdown must succeed: {e}"));
        assert!(quiescent.admissions_drained().unwrap());
        let checked = audit_clean_closed_fixture(&root, identity, range())
            .expect("child physical Bao must authenticate after actual shutdown");
        assert_eq!(checked, payload[START as usize..END as usize]);
        assert!(
            read_candidates(
                quiescent.owner(),
                identity.manifest.id.0,
                identity.manifest.size,
                IROH_PREORDER_16K,
            )
            .unwrap()
            .is_empty(),
            "no checkpoint claim from actor acceptance or shutdown alone"
        );
        quiescent.finish_clean(); // no LOCK_UN
        println!("{CLEAN_MARKER} actor_shutdown=true bao_verified=true");
        io::stdout().flush().unwrap();
        return;
    }

    // A dedicated process owns the store; cancellation of its *parent* future
    // must not create an abandoned actor/lease inside the long-lived parent.
    // On abnormal close the supervisor must forcibly terminate and reap it.
    struct ProcessGuard(Child);
    impl Drop for ProcessGuard {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    fn await_exit(child: &mut Child) -> std::process::ExitStatus {
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait().expect("OS process wait") {
                return status;
            }
            assert!(
                started.elapsed() < Duration::from_secs(50),
                "FsStore worker failed to terminate; guard will kill/reap it"
            );
            thread::sleep(Duration::from_millis(25));
        }
    }

    // Third path deliberately loses the parent IPC channel without a CLOSE.
    // This models a broken transport, not a proven parent process death.
    for (clean, broken_control) in [(true, false), (false, false), (false, true)] {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "staya-g2-05h3a-process-{}-{unique}",
            std::process::id()
        ));
        assert!(!root.exists(), "private root must never be preexisting");
        fs::create_dir(&root).expect("create disposable store");
        let mut child = ProcessGuard(
            Command::new(std::env::current_exe().expect("same test executable"))
                .arg("--exact")
                .arg("real_fsstore_os_process_supervisor_clean_and_kill")
                .arg("--nocapture")
                .env("STY_G2_05H3A_CHILD_ROOT", &root)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("launch dedicated real FsStore process"),
        );
        let stdout = child.0.stdout.take().expect("child process stdout");
        let (tx, rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut captured = String::new();
            for line in BufReader::new(stdout).lines() {
                let line = line.expect("child output UTF-8");
                if line.contains(READY_MARKER) {
                    let _ = tx.send(());
                }
                captured.push_str(&line);
                captured.push('\n');
            }
            captured
        });
        rx.recv_timeout(Duration::from_secs(70))
            .expect("real child must stage Bao and publish READY marker");

        // The parent has NOT acquired any store lock. The independently
        // running writer process is the only OS owner, not a parent thread.
        assert!(
            matches!(
                StoreLease::acquire(&root),
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock
            ),
            "second process cannot own an active child-owned FsStore"
        );
        if clean {
            writeln!(
                child.0.stdin.as_mut().expect("supervisor command channel"),
                "CLOSE"
            )
            .expect("request clean actor shutdown");
            drop(child.0.stdin.take()); // EOF after CLOSE
            assert!(
                await_exit(&mut child.0).success(),
                "clean worker must exit after actor shutdown"
            );
        } else if broken_control {
            // An unexpected control-channel EOF must not be mistaken for
            // CLEAN. The worker fails, its OS process exits, and the
            // supervisor reaps it before any independent custody attempt.
            drop(child.0.stdin.take());
            assert!(
                !await_exit(&mut child.0).success(),
                "lost parent control channel must fail closed"
            );
        } else {
            // Linux SIGKILL / Windows TerminateProcess. This is NOT fsync,
            // durable ACK or a guarantee partial Bao survived power-loss.
            child.0.kill().expect("terminate real active worker");
            assert!(
                !await_exit(&mut child.0).success(),
                "killed worker must not report a clean shutdown"
            );
        }
        let captured = reader.join().expect("read terminated child output");
        assert!(captured.contains(READY_MARKER));
        if clean {
            assert!(captured.contains(CLEAN_MARKER), "{captured}");
        } else {
            assert!(
                !captured.contains(CLEAN_MARKER),
                "killed process may not publish a clean-close marker"
            );
        }
        // The whole OS process (and all its Tokio actor threads) is gone.
        // Obtain the *next* independent lease before inspecting any bytes.
        let owner = StoreLease::acquire(&root).expect("post-join OS custody must be reacquirable");
        let payload = make_data();
        let (identity, _) = prepare(&payload);
        assert!(
            read_candidates(
                &owner,
                identity.manifest.id.0,
                identity.manifest.size,
                IROH_PREORDER_16K,
            )
            .unwrap()
            .is_empty(),
            "neither clean nor crash worker may publish candidate checkpoints"
        );
        if clean {
            let verified = audit_clean_closed_fixture(&root, identity, range())
                .expect("independent clean-reopen Bao authentication");
            assert_eq!(verified, payload[START as usize..END as usize]);
        } else {
            // No skip is authorized after crash. Physical Bao may or may not
            // authenticate; only a separate audit can later distinguish it.
            let _ = audit_clean_closed_fixture(&root, identity, range());
        }
        drop(owner);
        drop(child); // already joined; guard must not act on exited worker
        fs::remove_dir_all(&root).expect("delete only disposable CI directory");
        println!(
            "STY_G2_05H3A child_process=true mode={} join_confirmed=true \
             reacquire_after_exit=true checkpoint_published=false \
             clean_bao_verified={} kill_is_not_durable_ack=true file_gate=false",
            if clean {
                "clean"
            } else if broken_control {
                "broken_control"
            } else {
                "kill"
            },
            clean
        );
    }
}

/// G2-05h3b: The launcher never owns an FsStore lease. A separately launched
/// child owns the real pinned actor and lease, and its only parent-control
/// writer is an anonymous stdin pipe held by the launcher process.
/// The grandparent terminates the launcher with the native OS hard-kill API;
/// the orphaned writer must observe EOF, exit without a clean-ACK/checkpoint,
/// and leave the store available only after independent OS reacquisition.
/// This is a LAB proof of parent-channel loss, NOT authenticated production
/// IPC, a platform parent-death primitive, or durable partial-object resume.
#[tokio::test(flavor = "multi_thread")]
async fn real_fsstore_parent_death_fails_closed_without_clean_ack() {
    use std::{
        io::Read,
        path::PathBuf,
        process::{Child, Command, Stdio},
        thread,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    const PARENT_ENV: &str = "STY_G2_05H3B_LAUNCHER_ROOT";
    const CHILD_ENV: &str = "STY_G2_05H3B_OWNER_ROOT";
    const CHILD_READY: &str = ".g2-05h3b-child-ready";
    const PARENT_READY: &str = ".g2-05h3b-parent-ready";
    const CHILD_EOF: &str = ".g2-05h3b-orphan-saw-eof";
    const CHILD_ARMED: &str = ".g2-05h3b-owner-armed";
    const TEST_NAME: &str = "real_fsstore_parent_death_fails_closed_without_clean_ack";

    if let Some(root) = std::env::var_os(CHILD_ENV) {
        let root = PathBuf::from(root);
        let payload = make_data();
        let (identity, wire) = prepare(&payload);
        let required = range()
            .len()
            .checked_add(u64::try_from(wire.len()).unwrap())
            .unwrap();
        let active = ActiveFsStore::open(
            &root,
            Limits {
                max_partial_objects: 1,
                max_reserved_bytes: required,
                max_open_handles: 4,
                max_retries_per_object: 2,
            },
        )
        .await
        .expect("child opens the actual FsStore under its own OS lease");
        let cancelled = AtomicBool::new(false);
        let (_received, permit) = active
            .stage(identity, range(), &wire, &cancelled)
            .await
            .expect("stage authenticated physical Bao while child owns custody");
        drop(permit);
        fs::write(root.join(CHILD_READY), std::process::id().to_string()).unwrap();
        fs::File::open(root.join(CHILD_READY))
            .unwrap()
            .sync_all()
            .unwrap();

        // The only pipe writer belongs to the launcher. The launcher is
        // HARD-KILLED, not told to close stdin cleanly. A broken channel is
        // NOT a clean shutdown command, so no quiescence witness is issued.
        // Exchange a real command byte first: startup markers alone cannot
        // prove that the child's stdin is connected or still open on Windows.
        // Only after the ARM response may the grandparent test custody.
        let armed_path = root.join(CHILD_ARMED);
        let received = tokio::task::spawn_blocking(move || {
            let mut input = io::stdin().lock();
            let mut arm = [0u8; 1];
            input.read_exact(&mut arm).expect("private parent must send ARM");
            assert_eq!(arm, [b'A'], "unrecognized parent control command");
            fs::write(&armed_path, b"ARMED").unwrap();
            fs::File::open(&armed_path).unwrap().sync_all().unwrap();
            let mut control = [0u8; 1];
            input.read(&mut control)
        })
        .await
        .expect("blocking stdin reader must join")
        .expect("private pipe read must complete");
        assert_eq!(
            received, 0,
            "parent death must produce EOF, not an IPC command"
        );
        fs::write(root.join(CHILD_EOF), b"EOF_NO_CLEAN_ACK").unwrap();
        fs::File::open(root.join(CHILD_EOF))
            .unwrap()
            .sync_all()
            .unwrap();

        // The actor is still live; do NOT fabricate a clean shutdown from
        // EOF. Terminate this isolated writer process; OS close is the fence.
        // The next process must independently acquire and audit storage.
        std::process::exit(77);
    }

    if let Some(root) = std::env::var_os(PARENT_ENV) {
        let root = PathBuf::from(root);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_ENV, &root)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("launch independent writer child");
        assert!(
            child.stdin.is_some(),
            "launcher must own private pipe writer"
        );
        let started = Instant::now();
        while !root.join(CHILD_READY).is_file() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "writer exited before authenticating physical Bao"
            );
            assert!(
                started.elapsed() < Duration::from_secs(65),
                "child did not stage Bao under OS custody"
            );
            thread::sleep(Duration::from_millis(30));
        }
        // Do not report parent-ready until the writer has read an actual
        // pipe byte from this launcher while keeping the OS lease alive.
        child
            .stdin
            .as_mut()
            .expect("launcher owns private writer endpoint")
            .write_all(b"A")
            .expect("send ARM to live FsStore owner");
        child.stdin.as_mut().unwrap().flush().unwrap();
        let started = Instant::now();
        while !root.join(CHILD_ARMED).is_file() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "writer exited before acknowledging ARM"
            );
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "writer did not acknowledge actual private pipe byte"
            );
            thread::sleep(Duration::from_millis(30));
        }
        assert!(
            !root.join(CHILD_EOF).exists(),
            "writer saw EOF before the launcher was hard-killed"
        );
        fs::write(root.join(PARENT_READY), child.id().to_string()).unwrap();
        fs::File::open(root.join(PARENT_READY))
            .unwrap()
            .sync_all()
            .unwrap();

        // Remain alive and keep the writer-side stdin handle open. The
        // grandparent must kill this OS process rather than sending CLOSE.
        let started = Instant::now();
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "writer unexpectedly exited while launcher remained alive"
            );
            assert!(
                started.elapsed() < Duration::from_secs(120),
                "launcher was not hard-killed by the grandparent"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    struct KillLauncherOnDrop(Child);
    impl Drop for KillLauncherOnDrop {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("staya-g2-05h3b-{}-{unique}", std::process::id()));
    assert!(!root.exists(), "never reuse a private store directory");
    fs::create_dir(&root).expect("create disposable receiver directory");
    let mut launcher = KillLauncherOnDrop(
        Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(PARENT_ENV, &root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("launch parent-of-owner process"),
    );

    let started = Instant::now();
    while !root.join(PARENT_READY).is_file() {
        assert!(
            launcher.0.try_wait().unwrap().is_none(),
            "launcher died before child was confirmed active"
        );
        assert!(
            started.elapsed() < Duration::from_secs(80),
            "launcher's child never reached real FsStore-ready state"
        );
        thread::sleep(Duration::from_millis(30));
    }
    let child_pid: u32 = fs::read_to_string(root.join(PARENT_READY))
        .unwrap()
        .parse()
        .expect("grandparent must observe real child PID");
    assert!(child_pid > 0);
    assert!(root.join(CHILD_ARMED).exists(), "real pipe ARM must be observed");
    assert!(
        !root.join(CHILD_EOF).exists(),
        "pipe must not report EOF while parent remains alive"
    );
    let competing_owner = StoreLease::acquire(&root);
    assert!(
        matches!(
            &competing_owner,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock
        ),
        "real pinned FsStore child must exclude a second writer before parent death:          child_pid={child_pid} competing_owner={competing_owner:?}          armed={} eof={}",
        root.join(CHILD_ARMED).exists(),
        root.join(CHILD_EOF).exists(),
    );

    // Linux SIGKILL / Windows TerminateProcess: no Rust Drop, no explicit
    // CLOSE message, no guarantee that the worker's unsynced Bao survived.
    launcher.0.kill().expect("force-kill actual parent process");
    let ended = launcher.0.wait().expect("reap killed parent process");
    assert!(!ended.success(), "launcher must not exit cleanly");

    let started = Instant::now();
    while !root.join(CHILD_EOF).is_file() {
        assert!(
            started.elapsed() < Duration::from_secs(65),
            "orphaned writer failed to recognize loss of its only pipe writer"
        );
        thread::sleep(Duration::from_millis(30));
    }
    let observed = fs::read_to_string(root.join(CHILD_EOF)).unwrap();
    assert_eq!(observed, "EOF_NO_CLEAN_ACK");

    // Wait is only test observation of OS process cleanup, not a production
    // retry policy or an excuse to swallow WouldBlock. The independent
    // owner must still acquire a real lock and read only candidate metadata.
    let started = Instant::now();
    let mut observed_busy = 0usize;
    let owner = loop {
        match StoreLease::acquire(&root) {
            Ok(owner) => break owner,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                observed_busy += 1;
                assert!(
                    started.elapsed() < Duration::from_secs(30),
                    "writer child retained OS custody after failed-control exit"
                );
                thread::sleep(Duration::from_millis(25));
            }
            Err(e) => panic!("unexpected independent reacquisition error: {e}"),
        }
    };
    owner
        .validate_fence()
        .expect("cold owner must validate physical root");
    let payload = make_data();
    let (identity, _) = prepare(&payload);
    assert!(
        read_candidates(
            &owner,
            identity.manifest.id.0,
            identity.manifest.size,
            IROH_PREORDER_16K,
        )
        .unwrap()
        .is_empty(),
        "loss of launcher must never mint an authenticated checkpoint"
    );
    drop(owner);
    drop(launcher); // parent process already reaped
    fs::remove_dir_all(root).expect("remove private CI fixture only");
    println!(
        "STY_G2_05H3B real_fsstore=true parent_hard_killed=true \
         orphan_saw_eof=true clean_ack=false checkpoint=false \
         child_pid={child_pid} independent_owner=true busy_observations={observed_busy} \
         authenticated_ipc=false production_supervisor=false file_gate=false"
    );
}
