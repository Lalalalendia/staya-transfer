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
use partial_adapter::{audit_clean_closed_fixture, stage_verified_fixture};
use staya_transfer::{
    ByteRange, ContentId, Manifest,
    recovery::{BaoStorageProfile, StoreIdentity},
};
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    time::Duration,
};

const LEN: usize = 8 * 1024 * 1024 + 17;
const START: u64 = 33_333;
const END: u64 = 200_111;
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
        let payload = make_data();
        let (identity, wire) = prepare(&payload);
        let hash = Hash::from_bytes(identity.manifest.id.0);
        let store = FsStore::load(&root).await.expect("real pinned FsStore");

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
        let physical = audit_clean_closed_fixture(&root, identity, range())
            .expect("post-shutdown physically stored Bao must match root");
        assert_eq!(physical, payload[START as usize..END as usize]);

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

        fs::remove_dir_all(&root).expect("remove private fixture only");
        println!(
            "STY_G2_02 real_fsstore=true partial_bao_import=true clean_reopen=true physical_audit=true tamper_hold=true missing_outboard_hold=true crash_durable=false single_writer=false file_gate=false"
        );
    })
    .await
    .expect("bounded G2-02 partial-store fixture");
}
