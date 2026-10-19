//! STY-G2-02 experimental adapter for the pinned upstream iroh-blobs FsStore.
//!
//! NOT a production writer, durable checkpoint, OS-locked store, or Akula bridge.
//! A successful return means "the upstream actor accepted Bao items" ONLY.
//! There is no durable receipt; only separately audited bytes may be reused.

use bao_tree::{
    BaoTree, BlockSize, ByteRanges,
    io::{outboard::PreOrderOutboard, round_up_to_chunks, sync::valid_ranges},
};
use iroh_blobs::{
    Hash,
    protocol::ChunkRangesExt,
    store::fs::FsStore,
};
use staya_transfer::{
    ByteRange, TransferRequest,
    bao::{MAX_BAO_PROOF_BYTES, verify_bao_range},
    recovery::{BaoStorageProfile, StoreIdentity},
};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const BLOCK: BlockSize = BlockSize::from_chunk_log(4);

/// This result is NOT a durable acknowledgement and NEVER authorizes File Gate.
#[derive(Debug)]
pub struct AcceptedIntoUncommittedFsStore;

/// Verify a bounded, locally authorized Bao slice before letting the pinned
/// FsStore parse and stage it. Both checks use the same trusted object identity.
///
/// The caller must separately establish a private directory and sole OS writer
/// ownership before invoking this in any non-test environment.
pub async fn stage_verified_fixture(
    store: &FsStore,
    expected: StoreIdentity,
    range: ByteRange,
    wire: &[u8],
) -> Result<AcceptedIntoUncommittedFsStore, String> {
    if expected.profile != BaoStorageProfile::IrohBlobs0103PreOrder16KiB {
        return Err("unsupported Bao profile".to_owned());
    }
    // Durable partial storage requires complete 16 KiB Bao chunk groups.
    // Direct in-memory GET may use unaligned byte intervals, but do not stage
    // their incomplete boundary groups as independently recoverable.
    const GROUP_BYTES: u64 = 16 * 1024;
    if range.start() % GROUP_BYTES != 0
        || (range.end() != expected.manifest.size && range.end() % GROUP_BYTES != 0)
    {
        return Err("partial storage range is not Bao-group aligned".to_owned());
    }
    if wire.len() < 8 || wire.len() > MAX_BAO_PROOF_BYTES + 8 {
        return Err("wire response length out of bounds".to_owned());
    }
    let declared = u64::from_le_bytes(
        wire[..8].try_into().map_err(|_| "missing length prefix")?,
    );
    if declared != expected.manifest.size {
        return Err("wire object length differs from trusted manifest".to_owned());
    }
    let request =
        TransferRequest::new(expected.manifest, range.clone()).map_err(|e| format!("{e:?}"))?;
    // No untrusted peer assertion is ever enough to mint this type.
    let verified = verify_bao_range(&request, &wire[8..]).map_err(|e| format!("{e:?}"))?;
    if verified.bytes().len() as u64 != range.len() {
        return Err("independent Bao verifier returned wrong range".to_owned());
    }
    let hash = Hash::from_bytes(expected.manifest.id.0);
    let ranges = ChunkRanges::bytes(range.start()..range.end());
    store
        .blobs()
        .import_bao_bytes(hash, ranges, wire.to_vec())
        .await
        .map_err(|e| format!("pinned FsStore refused Bao import: {e}"))?;

    Ok(AcceptedIntoUncommittedFsStore)
}

/// Reconstruct proof from **actual test-only private** FsStore data/outboard
/// after a CLEAN shutdown and verify it independently through Staya.
///
/// This pathname-based fixture must NOT be called on attacker-accessible storage
/// or used for user files: it does NOT establish fd custody, snapshot isolation,
/// single writer, directory durability, disk quotas or verified journal ranges.
pub fn audit_clean_closed_fixture(
    private_root: &Path,
    expected: StoreIdentity,
    range: ByteRange,
) -> Result<Vec<u8>, String> {
    if expected.profile != BaoStorageProfile::IrohBlobs0103PreOrder16KiB {
        return Err("unsupported persisted profile".to_owned());
    }
    let hash = Hash::from_bytes(expected.manifest.id.0);
    let prefix = hash.to_hex();
    let data_path = private_root.join("data").join(format!("{prefix}.data"));
    let outboard_path = private_root.join("data").join(format!("{prefix}.obao4"));
    let data = fs::File::open(data_path).map_err(|e| format!("missing private data: {e}"))?;
    let outboard =
        fs::File::open(outboard_path).map_err(|e| format!("missing private Bao outboard: {e}"))?;

    // This file is intentionally sparse: G2 partial outboards contain only
    // paths needed by persisted ranges, not a complete 8 MiB proof tree.
    // encode_ranges_validated assumes all requested tree nodes are present and
    // can return UnexpectedEof on a legitimate sparse store. Instead walk
    // independently authenticated paths against the *trusted* full root.
    // Never derive trusted ranges from FsStore's disk bitfield alone.
    let _request =
        TransferRequest::new(expected.manifest, range.clone()).map_err(|e| format!("{e:?}"))?;
    if range.len() > staya_transfer::planner::MAX_PLANNED_RANGE_BYTES {
        return Err("physical audit request exceeds range limit".to_owned());
    }
    let tree = BaoTree::new(expected.manifest.size, BLOCK);
    let proof = PreOrderOutboard {
        root: blake3::Hash::from_bytes(expected.manifest.id.0),
        tree,
        data: &outboard,
    };
    let requested = round_up_to_chunks(&ByteRanges::from(range.start()..range.end()));
    let mut authenticated = ChunkRanges::empty();
    for result in valid_ranges(proof, &data, &requested) {
        let span = result.map_err(|e| format!("stored partial Bao validation failed: {e}"))?;
        authenticated |= ChunkRanges::from(span);
    }
    if !requested.is_subset(&authenticated) {
        return Err("physical data/outboard did not authenticate requested chunks".to_owned());
    }
    let mut data = data;
    let size = usize::try_from(range.len())
        .map_err(|_| "invalid audited range byte length")?;
    let mut verified = vec![0u8; size];
    data.seek(SeekFrom::Start(range.start()))
        .map_err(|e| format!("seek verified private data: {e}"))?;
    data.read_exact(&mut verified)
        .map_err(|e| format!("read verified private data: {e}"))?;
    Ok(verified)
}
