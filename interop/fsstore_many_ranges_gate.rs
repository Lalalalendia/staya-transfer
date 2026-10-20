//! STY-G2-06i — bounded REAL pinned FsStore with many disjoint Bao ranges.
//! A stress laboratory, not a durable checkpoint, production disk quota or
//! Akula File Gate. Each range authenticates against one immutable BLAKE3 root.

#[cfg(target_os = "linux")]
use bao_tree::{
    BlockSize, ByteRanges,
    io::{outboard::PreOrderMemOutboard, round_up_to_chunks, sync::encode_ranges_validated},
};
#[cfg(target_os = "linux")]
use iroh_blobs::store::fs::FsStore;
#[cfg(target_os = "linux")]
use staya_custody_lab::{
    StoreLease,
    admission::{Limits, SharedAdmission},
    checkpoint::{IROH_PREORDER_16K, read_candidates},
    disk_budget::{DiskLimits, inspect_quiescent_partial_files},
};
#[cfg(target_os = "linux")]
use staya_transfer::{
    ByteRange, ContentId, Manifest, TransferBudget,
    planner::{MissingRanges, VerifiedCheckpoint},
    recovery::{BaoStorageProfile, StoreIdentity},
};
#[cfg(target_os = "linux")]
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::AtomicBool,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "linux")]
#[path = "fsstore_partial_adapter.rs"]
mod partial_adapter;

#[cfg(target_os = "linux")]
const SIZE: usize = 8 * 1024 * 1024 + 17;
#[cfg(target_os = "linux")]
const COUNT: u64 = 64;
#[cfg(target_os = "linux")]
const GROUP: u64 = 16 * 1024;
#[cfg(target_os = "linux")]
const STEP: u64 = 64 * 1024;

#[cfg(target_os = "linux")]
fn payload() -> Vec<u8> {
    (0..SIZE).map(|i| ((i * 37 + 11) % 251) as u8).collect()
}

#[cfg(target_os = "linux")]
fn interval(index: u64) -> ByteRange {
    assert!(index < COUNT);
    let start = index * STEP + GROUP;
    ByteRange::new(start, start + GROUP, SIZE as u64)
        .expect("disjoint complete 16 KiB Bao chunk group")
}

#[cfg(target_os = "linux")]
fn wire(data: &[u8], outboard: &PreOrderMemOutboard, interval: &ByteRange) -> Vec<u8> {
    let requested = round_up_to_chunks(&ByteRanges::from(interval.start()..interval.end()));
    let mut bao = Vec::new();
    encode_ranges_validated(data, outboard, &requested, &mut bao)
        .expect("create Bao rooted in exact trusted manifest");
    let mut response = (data.len() as u64).to_le_bytes().to_vec();
    response.extend(bao);
    response
}

#[cfg(target_os = "linux")]
fn fd_count() -> usize {
    fs::read_dir("/proc/self/fd")
        .expect("Linux procfs FD inventory")
        .count()
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn real_fsstore_many_disjoint_bao_ranges_bound_resources_after_cold_reopen() {
    let trusted = payload();
    let outboard = PreOrderMemOutboard::create(&trusted, BlockSize::from_chunk_log(4));
    let identity = StoreIdentity {
        manifest: Manifest {
            id: ContentId(*outboard.root.as_bytes()),
            size: SIZE as u64,
        },
        profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
    };
    assert_eq!(identity.manifest.id.0, *blake3::hash(&trusted).as_bytes());

    if let Some(raw_root) = std::env::var_os("STY_G2_06I_COLD_ROOT") {
        let root = PathBuf::from(raw_root);
        let owner = StoreLease::acquire(&root).expect("independent cold OS custody");
        let reopened = FsStore::load(&root).await.expect("real pinned FsStore cold reopen");
        reopened.shutdown().await.expect("cold actor must quiesce before physical readback");

        assert!(
            read_candidates(
                &owner,
                identity.manifest.id.0,
                identity.manifest.size,
                IROH_PREORDER_16K
            )
            .expect("read only untrusted candidates")
            .is_empty(),
            "64 actor-accepted ranges cannot themselves mint one checkpoint"
        );
        // This ledger is produced exclusively AFTER physical Bao verification
        // by the cold independent process, not by the original in-memory sender.
        let mut physical_inventory = format!(
            "root={}\nobject_size={}\n",
            outboard.root.to_hex(),
            identity.manifest.size
        );
        for index in 0..COUNT {
            let range = interval(index);
            let start = range.start();
            let end = range.end();
            let expected = &trusted[start as usize..end as usize];
            let verified = partial_adapter::audit_clean_closed_fixture(&root, identity, range)
                .expect("cold independent sparse physical Bao proof");
            assert_eq!(verified, expected, "wrong cold Bao group {index}");
            physical_inventory.push_str(&format!(
                "group={index} start={start} end={end} blake3={}\n",
                blake3::hash(&verified).to_hex()
            ));
        }

        // Even many physically authentic groups have ZERO durable skip
        // authority without a separately published and re-audited checkpoint.
        let empty = VerifiedCheckpoint::empty(identity.manifest);
        let total_missing: u64 = MissingRanges::from_checkpoint(
            identity.manifest,
            &empty,
            TransferBudget {
                max_inflight_bytes: 1024 * 1024,
                max_sources: 1,
                max_retries: 0,
            },
        )
        .unwrap()
        .map(|range| range.len())
        .sum();
        assert_eq!(total_missing, SIZE as u64);
        if let Some(dir) = std::env::var_os("STY_G2_06I_OUTPUT_DIR") {
            let dir = PathBuf::from(dir);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("physical-ranges.txt"), physical_inventory).unwrap();
        }
        drop(owner);
        println!("STY_G2_06I_COLD actor_reopen=true audited_groups=64 candidates=0 skip=false");
        return;
    }

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "staya-g2-06i-{}-{}-{suffix}",
        std::process::id(),
        std::env::var("STY_INTEROP_VARIANT").unwrap_or_else(|_| "local".to_owned())
    ));
    assert!(!root.exists());
    fs::create_dir(&root).expect("own new disposable FsStore root");

    let owner = StoreLease::acquire(&root).expect("exclusive real FsStore custody");
    let actor = FsStore::load(&root).await.expect("actual pinned FsStore actor");
    let ledger = SharedAdmission::new(Limits {
        max_partial_objects: 1,
        max_reserved_bytes: 128 * 1024,
        max_open_handles: 4,
        max_retries_per_object: 2,
    })
    .unwrap();
    let cancelled = AtomicBool::new(false);
    let baseline_fds = fd_count();
    let mut highwater_fds = baseline_fds;
    let mut max_wire = 0usize;

    // A memory-bounded test: never materialize all proofs or ranges in a
    // vector. Import and release one locally authenticated Bao interval at a
    // time, then ensure no in-flight admission is silently leaked.
    tokio::time::timeout(Duration::from_secs(180), async {
        for index in 0..COUNT {
            let range = interval(index);
            let proof = wire(&trusted, &outboard, &range);
            max_wire = max_wire.max(proof.len());
            assert!(proof.len() <= 128 * 1024, "single Bao proof unexpectedly unbounded");
            let (_staged, permit) = partial_adapter::stage_with_inflight_budget(
                &owner,
                &ledger,
                &actor,
                identity,
                range,
                &proof,
                &cancelled,
            )
            .await
            .expect("pinned FsStore must accept exact authenticated Bao group");
            assert_eq!(ledger.usage().unwrap().0, 1);
            drop(permit);
            assert_eq!(ledger.usage().unwrap(), (0, 0, 0));
            highwater_fds = highwater_fds.max(fd_count());
            assert!(
                highwater_fds <= baseline_fds + 32,
                "open handles grew with disjoint accepted range count"
            );
        }
    })
    .await
    .expect("bounded 64-range actor import must not hang");

    ledger.stop_admissions().unwrap();
    assert!(ledger.admissions_drained().unwrap());
    actor.shutdown().await.expect("all actual actor writers quiesced");
    drop(actor);
    let disk = inspect_quiescent_partial_files(
        &owner,
        DiskLimits {
            max_entries: 16,
            max_objects: 1,
            max_logical_bytes: 16 * 1024 * 1024,
        },
    )
    .expect("single object remains within conservative quiescent file quota");
    assert_eq!(disk.objects, 1);
    assert!(disk.entries >= 2, "physical data and outboard must both exist");
    assert!(
        read_candidates(
            &owner,
            identity.manifest.id.0,
            identity.manifest.size,
            IROH_PREORDER_16K,
        )
        .unwrap()
        .is_empty(),
        "bare actor shutdown cannot publish a checkpoint"
    );
    drop(owner);

    let cold = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("real_fsstore_many_disjoint_bao_ranges_bound_resources_after_cold_reopen")
        .arg("--nocapture")
        .env("STY_G2_06I_COLD_ROOT", &root)
        .output()
        .expect("launch independent cold FsStore verifier");
    assert!(
        cold.status.success(),
        "64 cold physical Bao audits failed: {}",
        String::from_utf8_lossy(&cold.stderr)
    );
    assert!(
        String::from_utf8_lossy(&cold.stdout).contains("STY_G2_06I_COLD"),
        "second OS process did not run cold verification"
    );
    fs::remove_dir_all(&root).expect("delete only owned disposable test store");

    // Large *logical* sparse objects: the planner must remain lazy. This
    // does not imply a 1-TiB physical FsStore object has been tested.
    let enormous = Manifest {
        id: ContentId([0x42; 32]),
        size: (1_u64 << 40) + 17,
    };
    let empty = VerifiedCheckpoint::empty(enormous);
    let planned: Vec<_> = MissingRanges::from_checkpoint(
        enormous,
        &empty,
        TransferBudget {
            max_inflight_bytes: 1024 * 1024,
            max_sources: 1,
            max_retries: 0,
        },
    )
    .unwrap()
    .take(16)
    .collect();
    assert_eq!(planned.len(), 16);
    for (index, range) in planned.iter().enumerate() {
        assert_eq!(range.start(), index as u64 * 1024 * 1024);
        assert_eq!(range.len(), 1024 * 1024);
    }

    if let Some(dir) = std::env::var_os("STY_G2_06I_OUTPUT_DIR") {
        let dir = PathBuf::from(dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(
            dir.join("physical-ranges.txt").is_file(),
            "separate OS process did not save its 64 root-authenticated physical ranges"
        );
        fs::write(
            dir.join("inventory.txt"),
            "real_fsstore_groups=64\nphysical_bao_readback=64\ncheckpoint_candidates=0\nredownload=full\nobject_count=1\nlogical_disk_bounded=true\ninflight_permit_leaks=0\nfile_descriptor_growth_bounded=true\nsparse_planner_size_gt_1TiB=true\nfile_gate=false\n",
        )
        .unwrap();
    }
    println!(
        "STY_G2_06I fsstore=true groups=64 cold_bao=64 max_wire={} fd_growth={} quota_drained=true skip=false",
        max_wire,
        highwater_fds - baseline_fds
    );
}
