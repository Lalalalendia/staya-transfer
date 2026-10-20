//! STY-G2-06h: real kernel ENOSPC during pinned iroh-blobs FsStore I/O.
//! CI must also prove an actual physical sidecar pwrite returned ENOSPC;
//! a simulated /dev/full audit callback is NOT sufficient.

#[cfg(target_os = "linux")]
use bao_tree::{
    BlockSize, ByteRanges,
    io::{outboard::PreOrderMemOutboard, round_up_to_chunks, sync::encode_ranges_validated},
};
#[cfg(target_os = "linux")]
use iroh_blobs::{Hash, store::fs::FsStore};
#[cfg(target_os = "linux")]
use staya_custody_lab::{
    StoreLease,
    checkpoint::{IROH_PREORDER_16K, read_candidates},
};
#[cfg(target_os = "linux")]
use staya_transfer::{
    ByteRange, ContentId, Manifest, TransferBudget,
    planner::{MissingRanges, VerifiedCheckpoint},
    recovery::{BaoStorageProfile, StoreIdentity},
};
#[cfg(target_os = "linux")]
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process::Command,
    time::Duration,
};
#[cfg(target_os = "linux")]
#[path = "fsstore_partial_adapter.rs"]
mod partial_adapter;

#[cfg(target_os = "linux")]
const OBJECT_LEN: usize = 8 * 1024 * 1024 + 17;

#[cfg(target_os = "linux")]
fn bytes() -> Vec<u8> {
    (0..OBJECT_LEN)
        .map(|i| ((i * 37 + 11) % 251) as u8)
        .collect()
}

#[cfg(target_os = "linux")]
fn bao_wire(data: &[u8], outboard: &PreOrderMemOutboard, from: u64, to: u64) -> Vec<u8> {
    let chunks = round_up_to_chunks(&ByteRanges::from(from..to));
    let mut proof = Vec::new();
    encode_ranges_validated(data, outboard, &chunks, &mut proof)
        .expect("locally root-authenticated Bao proof");
    let mut wire = (data.len() as u64).to_le_bytes().to_vec();
    wire.extend_from_slice(&proof);
    wire
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn real_fsstore_enospc_rejects_writer_and_cold_restart() {
    const FIRST_START: u64 = 32_768;
    const FIRST_END: u64 = 196_608;
    const FAILED_START: u64 = 393_216;
    const FAILED_END: u64 = 557_056;

    let root = PathBuf::from(
        std::env::var_os("STY_G2_06H_ROOT")
            .expect("isolated size-bounded mounted tmpfs root required"),
    );
    assert!(root.is_dir());
    let data = bytes();
    let outboard = PreOrderMemOutboard::create(&data, BlockSize::from_chunk_log(4));
    let identity = StoreIdentity {
        manifest: Manifest {
            id: ContentId(*outboard.root.as_bytes()),
            size: OBJECT_LEN as u64,
        },
        profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
    };
    assert_eq!(identity.manifest.id.0, *blake3::hash(&data).as_bytes());

    if std::env::var_os("STY_G2_06H_COLD").is_some() {
        let owner = StoreLease::acquire(&root).expect("independent post-ENOSPC custody");
        assert!(
            read_candidates(
                &owner,
                identity.manifest.id.0,
                identity.manifest.size,
                IROH_PREORDER_16K
            )
            .unwrap()
            .is_empty(),
            "a failed FsStore import cannot mint a usable checkpoint"
        );
        let reopened = FsStore::load(&root).await.expect("real cold FsStore reopen");
        let missing: u64 = MissingRanges::from_checkpoint(
            identity.manifest,
            &VerifiedCheckpoint::empty(identity.manifest),
            TransferBudget {
                max_inflight_bytes: 1024 * 1024,
                max_sources: 1,
                max_retries: 0,
            },
        )
        .unwrap()
        .map(|part| part.len())
        .sum();
        assert_eq!(missing, OBJECT_LEN as u64, "recovery must redownload everything");
        reopened.shutdown().await.expect("cold actor shutdown");
        // Physical data may or may not survive disk-full. Even an authentic
        // partial range without a checkpoint cannot authorize a skip.
        let preserved = partial_adapter::audit_clean_closed_fixture(
            &root,
            identity,
            ByteRange::new(FIRST_START, FIRST_END, identity.manifest.size).unwrap(),
        )
        .is_ok();
        drop(owner);
        println!(
            "STY_G2_06H_COLD second_os_process=true candidates=0 redownload=full first_physical_valid={preserved}"
        );
        return;
    }

    let owner = StoreLease::acquire(&root).expect("exclusive real FsStore lease");
    let actor = FsStore::load(&root).await.expect("real pinned FsStore");
    let first = ByteRange::new(FIRST_START, FIRST_END, identity.manifest.size).unwrap();
    partial_adapter::stage_verified_fixture(
        &actor,
        identity,
        first,
        &bao_wire(&data, &outboard, FIRST_START, FIRST_END),
    )
    .await
    .expect("first valid Bao import succeeds before disk is full");
    let hash = Hash::from_bytes(identity.manifest.id.0).to_hex();
    assert!(
        root.join("data").join(format!("{hash}.data")).is_file(),
        "real FsStore physical .data must exist"
    );
    assert!(
        read_candidates(
            &owner,
            identity.manifest.id.0,
            identity.manifest.size,
            IROH_PREORDER_16K
        )
        .unwrap()
        .is_empty()
    );

    let filler_path = root.join("g2-06h-volume-filler");
    let mut filler = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&filler_path)
        .unwrap();
    let mut filled = 0u64;
    let mut kernel_enospc = false;
    for _ in 0..(48 * 1024 * 1024 / 4096) {
        match filler.write_all(&[0x5a; 4096]) {
            Ok(()) => filled += 4096,
            Err(e) if e.raw_os_error() == Some(28) => {
                kernel_enospc = true;
                break;
            }
            Err(e) => panic!("filler failed with non-ENOSPC {e:?}"),
        }
    }
    assert!(kernel_enospc, "filesystem was never exhausted by real writes");
    assert!(filled > 1024 * 1024, "unexpectedly small isolated mount");

    // Different 16-KiB Bao groups must allocate new .data pages.
    let failed = ByteRange::new(FAILED_START, FAILED_END, identity.manifest.size).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        partial_adapter::stage_verified_fixture(
            &actor,
            identity,
            failed,
            &bao_wire(&data, &outboard, FAILED_START, FAILED_END),
        ),
    )
    .await
    .expect("real FsStore must return instead of hanging");
    let actual_error = result.expect_err("real FsStore cannot import on full tmpfs");
    println!("STY_G2_06H_ACTOR_REJECTED={actual_error}");
    assert!(
        read_candidates(
            &owner,
            identity.manifest.id.0,
            identity.manifest.size,
            IROH_PREORDER_16K
        )
        .unwrap()
        .is_empty(),
        "disk-full IO must not create a checkpoint or grant skipped bytes"
    );

    drop(filler);
    fs::remove_file(&filler_path).expect("release only test-created filler");
    tokio::time::timeout(Duration::from_secs(30), actor.shutdown())
        .await
        .expect("actor shutdown must not hang after space is freed")
        .expect("actor must shut down after ENOSPC");
    drop(owner);

    let child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("real_fsstore_enospc_rejects_writer_and_cold_restart")
        .arg("--nocapture")
        .env("STY_G2_06H_COLD", "1")
        .env("STY_G2_06H_ROOT", &root)
        .output()
        .expect("launch independent post-ENOSPC process");
    assert!(
        child.status.success(),
        "cold reopen failed: {}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(
        String::from_utf8_lossy(&child.stdout).contains("STY_G2_06H_COLD"),
        "independent recovery logic must execute"
    );
    if let Some(dir) = std::env::var_os("STY_G2_06H_OUTPUT_DIR") {
        let dir = PathBuf::from(dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("inventory.txt"),
            "real_tmpfs_enospc=true\nfsstore_first_import=true\nfsstore_second_import_rejected=true\ncheckpoint_candidates=0\nseparate_process_reopen=true\nredownload=full\nretained_skip=false\n",
        )
        .unwrap();
    }
    println!("STY_G2_06H real_fsstore=true real_enospc=true no_skip=true file_gate=false");
}
