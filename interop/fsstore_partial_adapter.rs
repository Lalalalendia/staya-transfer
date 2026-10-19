//! STY-G2-02 experimental adapter for the pinned upstream iroh-blobs FsStore.
//!
//! NOT a production writer, durable checkpoint, OS-locked store, or Akula bridge.
//! A successful return means "the upstream actor accepted Bao items" ONLY.
//! There is no durable receipt; only separately audited bytes may be reused.

use bao_tree::{
    BaoTree, BlockSize, ByteRanges, ChunkRanges,
    io::{outboard::PreOrderOutboard, round_up_to_chunks, sync::valid_ranges},
};
use iroh_blobs::{Hash, protocol::ChunkRangesExt, store::fs::FsStore};
use staya_custody_lab::{
    StoreLease,
    admission::{InflightPermit, Reservation, SharedAdmission},
};
use staya_transfer::{
    ByteRange, TransferRequest,
    bao::{MAX_BAO_PROOF_BYTES, verify_bao_range},
    recovery::{BaoStorageProfile, StoreIdentity},
};
use std::sync::atomic::{AtomicBool, Ordering};
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
    if !range.start().is_multiple_of(GROUP_BYTES)
        || (range.end() != expected.manifest.size && !range.end().is_multiple_of(GROUP_BYTES))
    {
        return Err("partial storage range is not Bao-group aligned".to_owned());
    }
    if wire.len() < 8 || wire.len() > MAX_BAO_PROOF_BYTES + 8 {
        return Err("wire response length out of bounds".to_owned());
    }
    let declared = u64::from_le_bytes(wire[..8].try_into().map_err(|_| "missing length prefix")?);
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

/// G2-05f: bound the *in-flight* partial Bao import while a cooperating
/// process holds the OS store lease. The returned permit remains live until
/// the caller finishes with the uncommitted staged range.
///
/// The logical byte budget accounts for decoded range plus incoming proof
/// bytes; it is NOT a physical disk-space or memory allocator quota. On
/// cancellation after actor submission, the actor may already have written
/// verified bytes: we return an error, never a durable checkpoint or a
/// verified post-restart range. Cancellation cannot interrupt an upstream
/// FsStore actor already processing the accepted import.
// This shared test adapter is also compiled by fsstore_crash_gate, which
// deliberately does not exercise G2-05f admission. The function is used by
// fsstore_partial_gate on both pinned dependency variants.
#[allow(dead_code, reason = "used by the partial-import test, not by the crash test")]
pub async fn stage_with_inflight_budget(
    owner: &StoreLease,
    ledger: &SharedAdmission,
    store: &FsStore,
    expected: StoreIdentity,
    range: ByteRange,
    wire: &[u8],
    cancelled: &AtomicBool,
) -> Result<(AcceptedIntoUncommittedFsStore, InflightPermit), String> {
    owner
        .validate_fence()
        .map_err(|err| format!("store ownership is invalid: {err}"))?;
    if cancelled.load(Ordering::Acquire) {
        return Err("import cancelled before store admission".to_owned());
    }
    let wire_size =
        u64::try_from(wire.len()).map_err(|_| "incoming Bao proof length cannot fit accounting")?;
    let logical_bytes = range
        .len()
        .checked_add(wire_size)
        .ok_or("incoming plus decoded byte budget overflow")?;
    let request = Reservation::new(1, logical_bytes, 4)
        .map_err(|err| format!("invalid in-flight resource request: {err}"))?;
    let permit = ledger
        .reserve(request)
        .map_err(|err| format!("FsStore admission denied: {err}"))?;
    if cancelled.load(Ordering::Acquire) {
        return Err("import cancelled while reserved, before actor call".to_owned());
    }
    let accepted = stage_verified_fixture(store, expected, range, wire).await?;
    owner
        .validate_fence()
        .map_err(|err| format!("store ownership lost after uncommitted import: {err}"))?;
    if cancelled.load(Ordering::Acquire) {
        return Err("import cancelled after staging; no checkpoint authorized".to_owned());
    }
    Ok((accepted, permit))
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
    let size = usize::try_from(range.len()).map_err(|_| "invalid audited range byte length")?;
    let mut verified = vec![0u8; size];
    data.seek(SeekFrom::Start(range.start()))
        .map_err(|e| format!("seek verified private data: {e}"))?;
    data.read_exact(&mut verified)
        .map_err(|e| format!("read verified private data: {e}"))?;
    Ok(verified)
}
