//! STY-G2-05g: physical lengths of the REAL pinned partial FsStore.
//! Logical file lengths are NOT real allocated disk usage or capacity.
#[path = "fsstore_partial_adapter.rs"]
mod partial_adapter;

use bao_tree::{
    BlockSize, ByteRanges,
    io::{outboard::PreOrderMemOutboard, round_up_to_chunks, sync::encode_ranges_validated},
};
use iroh_blobs::store::fs::FsStore;
use partial_adapter::{audit_clean_closed_fixture, stage_verified_fixture};
use staya_custody_lab::{
    StoreLease,
    checkpoint::{IROH_PREORDER_16K, read_candidates},
    disk_budget::{DiskLimits, inspect_quiescent_partial_files},
};
use staya_transfer::{
    ByteRange, ContentId, Manifest,
    recovery::{BaoStorageProfile, StoreIdentity},
};
use std::{fs, time::Duration};

const LEN: usize = 1_048_593;
const END: u64 = 32_768;

#[tokio::test(flavor = "multi_thread")]
async fn real_pinned_fsstore_quiescent_disk_snapshot_has_bounded_refusal() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let root = std::env::temp_dir().join(format!(
            "staya-g2-05g-real-{}-{}",
            std::process::id(),
            std::env::var("STY_INTEROP_VARIANT").unwrap_or_else(|_| "ci".to_owned()),
        ));
        assert!(!root.exists());
        fs::create_dir(&root).unwrap();
        let owner = StoreLease::acquire(&root).unwrap();
        let data: Vec<u8> = (0..LEN)
            .map(|i| ((i * 37 + 11) % 251) as u8)
            .collect();
        let outboard = PreOrderMemOutboard::create(&data, BlockSize::from_chunk_log(4));
        let expected = StoreIdentity {
            manifest: Manifest {
                id: ContentId(*outboard.root.as_bytes()),
                size: LEN as u64,
            },
            profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
        };
        assert_eq!(&expected.manifest.id.0, blake3::hash(&data).as_bytes());
        let range = ByteRange::new(0, END, LEN as u64).unwrap();
        let mut proof = Vec::new();
        let requested = round_up_to_chunks(&ByteRanges::from(0..END));
        encode_ranges_validated(&data, &outboard, &requested, &mut proof).unwrap();
        let mut wire = (LEN as u64).to_le_bytes().to_vec();
        wire.extend_from_slice(&proof);

        let store = FsStore::load(&root).await.expect("pinned actual FsStore");
        stage_verified_fixture(&store, expected, range.clone(), &wire)
            .await
            .expect("real verified Bao import");
        store.shutdown().await.expect("quiescent FsStore required before snapshot");
        drop(store);

        let limits = DiskLimits {
            max_entries: 16,
            max_objects: 1,
            max_logical_bytes: 16 * 1024 * 1024,
        };
        let observed = inspect_quiescent_partial_files(&owner, limits)
            .expect("real pinned partial files must fit local logical budget");
        assert_eq!(observed.objects, 1);
        assert!(observed.entries >= 4);
        assert!(observed.logical_bytes > 0);
        let denied = DiskLimits {
            max_logical_bytes: observed.logical_bytes - 1,
            ..limits
        };
        assert!(
            inspect_quiescent_partial_files(&owner, denied).is_err(),
            "one byte below current logical files must fail closed"
        );
        let bytes = audit_clean_closed_fixture(&root, expected, range)
            .expect("independent actual sparse Bao physical audit");
        assert_eq!(bytes, data[..END as usize]);
        assert!(
            read_candidates(
                &owner,
                expected.manifest.id.0,
                expected.manifest.size,
                IROH_PREORDER_16K
            )
            .unwrap()
            .is_empty(),
            "storage observation does not mint a checkpoint or a verified skip"
        );
        drop(owner);
        fs::remove_dir_all(root).unwrap();
        println!(
            "STY_G2_05G real_fsstore=true bounded_logical_files=true physical_bao=true actual_enospc_in_fsstore=false durable_ack=false file_gate=false"
        );
    })
    .await
    .expect("bounded pinned FsStore storage snapshot test");
}
