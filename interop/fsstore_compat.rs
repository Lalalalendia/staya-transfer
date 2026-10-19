//! Genuine pinned FsStore outboard -> independently verified Staya Bao range.
//! No network, Akula user content, File Gate or production publication.

use bao_tree::{
    BaoTree, BlockSize, ByteRanges,
    io::{outboard::PreOrderOutboard, round_up_to_chunks, sync::encode_ranges_validated},
};
use iroh_blobs::{Hash, store::fs::FsStore};
use staya_transfer::{
    ByteRange, ContentId, Manifest, TransferError, TransferRequest, bao::verify_bao_range,
};
use std::{fs, path::PathBuf};

const DATA_LEN: usize = 8 * 1024 * 1024 + 17;
const START: u64 = 33_333;
const END: u64 = 200_111;
const BLOCK: BlockSize = BlockSize::from_chunk_log(4);

fn payload() -> Vec<u8> {
    (0..DATA_LEN).map(|i| ((i * 37 + 11) % 251) as u8).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_fsstore_bao_outboard_authenticates_in_staya() {
    let root = std::env::temp_dir().join(format!(
        "staya-g1d-{}-{}",
        std::process::id(),
        std::env::var("STY_INTEROP_VARIANT").unwrap_or_else(|_| "local".to_owned()),
    ));
    assert!(!root.exists(), "never reuse test files");
    fs::create_dir(&root).unwrap();

    let data = payload();
    let root_hash = Hash::new(&data);
    assert_eq!(*root_hash.as_bytes(), *blake3::hash(&data).as_bytes());
    let store = FsStore::load(&root).await.expect("create FsStore");
    let tag = store
        .add_slice(&data)
        .await
        .expect("add real external data");
    assert_eq!(tag.hash, root_hash);
    store.shutdown().await.expect("durably close store");
    drop(store);

    let hex = root_hash.to_hex().to_string();
    let data_path = root.join("data").join(format!("{hex}.data"));
    let bao_path = root.join("data").join(format!("{hex}.obao4"));
    assert_eq!(fs::metadata(&data_path).unwrap().len(), DATA_LEN as u64);
    assert_eq!(fs::read(&data_path).unwrap(), data);
    let tree = BaoTree::new(DATA_LEN as u64, BLOCK);
    let parent_len = tree.outboard_size();
    assert!(parent_len > 0);
    assert_eq!(fs::metadata(&bao_path).unwrap().len(), parent_len);

    let proof_file = fs::File::open(&bao_path).unwrap();
    let data_file = fs::File::open(&data_path).unwrap();
    let stored_proof = PreOrderOutboard {
        root: blake3::Hash::from_bytes(*root_hash.as_bytes()),
        tree,
        data: &proof_file,
    };
    let chunks = round_up_to_chunks(&ByteRanges::from(START..END));
    let mut response = Vec::new();
    encode_ranges_validated(&data_file, stored_proof, &chunks, &mut response)
        .expect("encode from real .obao4");
    assert!(!response.is_empty());

    let request = TransferRequest::new(
        Manifest {
            id: ContentId(*root_hash.as_bytes()),
            size: DATA_LEN as u64,
        },
        ByteRange::new(START, END, DATA_LEN as u64).unwrap(),
    )
    .unwrap();
    let verified = verify_bao_range(&request, &response).unwrap();
    assert_eq!(verified.bytes(), &data[START as usize..END as usize]);
    assert_eq!(verified.manifest(), request.manifest);
    assert_eq!(verified.range(), &request.range);

    let mut poisoned = response.clone();
    let flip_at = poisoned.len() / 2;
    poisoned[flip_at] ^= 0x40;
    assert!(matches!(
        verify_bao_range(&request, &poisoned),
        Err(TransferError::CorruptData)
    ));
    let mut trailing = response.clone();
    trailing.push(0);
    assert!(matches!(
        verify_bao_range(&request, &trailing),
        Err(TransferError::CorruptData)
    ));
    let wrong = TransferRequest::new(
        Manifest {
            id: ContentId([0x7f; 32]),
            size: DATA_LEN as u64,
        },
        request.range.clone(),
    )
    .unwrap();
    assert!(matches!(
        verify_bao_range(&wrong, &response),
        Err(TransferError::CorruptData)
    ));

    if let Ok(destination) = std::env::var("STY_INTEROP_OUTPUT_DIR") {
        let out = PathBuf::from(destination);
        fs::create_dir_all(&out).unwrap();
        fs::write(out.join("proof.bin"), &response).unwrap();
        fs::write(
            out.join("manifest.txt"),
            format!(
                "blake3={}\nsize={}\nstart={}\nend={}\noutboard={}\n",
                root_hash.to_hex(),
                DATA_LEN,
                START,
                END,
                parent_len
            ),
        )
        .unwrap();
    }

    drop(tag);
    drop(data_file);
    drop(proof_file);
    fs::remove_dir_all(&root).unwrap();
    println!(
        "STY_G1D_FSSTORE_INTEROP data={} outboard={} bao=true tamper_hold=true trailing_hold=true wrong_root_hold=true file_gate_ready=false",
        DATA_LEN, parent_len,
    );
}
