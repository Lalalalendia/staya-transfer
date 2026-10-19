//! Bounded in-memory Bao proof verification for an immutable object range.
//!
//! This is a deliberately small testable adapter to bao-tree, the proof codec
//! also used by iroh-blobs. It has no sockets, no disk persistence, no user ACL
//! and no authority to publish or overwrite an Akula document.
//!
//! Security: the caller must obtain the Manifest from a trusted, authorized
//! source. A malicious peer may supply arbitrary encoded bytes. Only a fully
//! decoded, root-checked proof yields VerifiedBaoRange.

use std::io::Cursor;

use bao_tree::{
    BaoTree, BlockSize, ByteRanges, blake3,
    io::{BaoContentItem, round_up_to_chunks, sync::DecodeResponseIter},
};

use crate::{
    ByteRange, Manifest, TransferError, TransferRequest, planner::MAX_PLANNED_RANGE_BYTES,
};

/// Same 16 KiB chunk-group size used by iroh-blobs.
const IROH_BLOCK_SIZE: BlockSize = BlockSize::from_chunk_log(4);

/// This covers one 1 MiB request and bounded authentication-tree overhead.
/// The adapter rejects a proof larger than this before decoding.
pub const MAX_BAO_PROOF_BYTES: usize = 2 * 1024 * 1024;

/// An in-memory range successfully authenticated against an exact BLAKE3 root.
///
/// The fields and constructor are private. This type is not durable storage,
/// a user authorization grant, or a file application receipt.
#[derive(Debug)]
pub struct VerifiedBaoRange {
    manifest: Manifest,
    range: ByteRange,
    bytes: Vec<u8>,
}

impl VerifiedBaoRange {
    pub fn manifest(&self) -> Manifest {
        self.manifest
    }

    pub fn range(&self) -> &ByteRange {
        &self.range
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume verified data only after a trusted storage layer has chosen
    /// where the bytes may be stored. Does not publish an Akula revision.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Verify exactly one requested range from a Bao-encoded response.
///
/// A decoder is trusted only if it successfully validates all requested
/// leaves against the expected BLAKE3 root, covers each requested byte
/// exactly once, and consumes the complete response without trailing data.
/// This wrapper caps both input and output memory to small bounded amounts.
///
/// A range proof must be encoded with the iroh-blobs 16 KiB block-group
/// profile. It contains no 8-byte length prefix: the expected length is
/// already part of the trusted Manifest.
pub fn verify_bao_range(
    request: &TransferRequest,
    encoded: &[u8],
) -> Result<VerifiedBaoRange, TransferError> {
    let start = request.range.start();
    let end = request.range.end();
    let size = request.manifest.size;

    if start >= end || end > size {
        return Err(TransferError::InvalidRange);
    }
    if request.range.len() > MAX_PLANNED_RANGE_BYTES || encoded.len() > MAX_BAO_PROOF_BYTES {
        return Err(TransferError::InvalidBudget);
    }

    let tree = BaoTree::new(size, IROH_BLOCK_SIZE);
    let root = blake3::Hash::from_bytes(request.manifest.id.0);
    let byte_ranges = ByteRanges::from(start..end);
    let chunk_ranges = round_up_to_chunks(&byte_ranges);

    let mut encoded_reader = Cursor::new(encoded);
    let mut verified = Vec::with_capacity(request.range.len() as usize);
    let mut cursor = start;

    for item in DecodeResponseIter::new(root, tree, &mut encoded_reader, &chunk_ranges) {
        match item.map_err(|_| TransferError::CorruptData)? {
            BaoContentItem::Parent(_) => {}
            BaoContentItem::Leaf(leaf) => {
                let leaf_start = leaf.offset;
                let leaf_end = leaf_start
                    .checked_add(leaf.data.len() as u64)
                    .ok_or(TransferError::CorruptData)?;
                let copy_start = start.max(leaf_start);
                let copy_end = end.min(leaf_end);

                if copy_start >= copy_end {
                    continue;
                }
                if copy_start != cursor {
                    return Err(TransferError::CorruptData);
                }

                let offset = (copy_start - leaf_start) as usize;
                let count = (copy_end - copy_start) as usize;
                let slice = leaf
                    .data
                    .get(offset..offset + count)
                    .ok_or(TransferError::CorruptData)?;
                verified.extend_from_slice(slice);
                cursor = copy_end;
            }
        }
    }

    if cursor != end
        || encoded_reader.position() != encoded.len() as u64
        || verified.len() as u64 != request.range.len()
    {
        return Err(TransferError::CorruptData);
    }

    Ok(VerifiedBaoRange {
        manifest: request.manifest,
        range: request.range.clone(),
        bytes: verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContentId, TransferRequest};
    use bao_tree::io::outboard::PreOrderMemOutboard;
    use bao_tree::io::sync::encode_ranges_validated;

    fn fixture(data: &[u8], range: std::ops::Range<u64>) -> (TransferRequest, Vec<u8>) {
        let outboard = PreOrderMemOutboard::create(data, IROH_BLOCK_SIZE);
        let manifest = Manifest {
            id: ContentId(*outboard.root.as_bytes()),
            size: data.len() as u64,
        };
        let desired = ByteRange::new(range.start, range.end, manifest.size).unwrap();
        let req = TransferRequest::new(manifest, desired).unwrap();

        let chunk_ranges = round_up_to_chunks(&ByteRanges::from(range));
        let mut encoded = Vec::new();
        encode_ranges_validated(data, &outboard, &chunk_ranges, &mut encoded).unwrap();
        (req, encoded)
    }

    fn sample_data() -> Vec<u8> {
        (0..(80 * 1024 + 13))
            .map(|n| ((n * 13 + 7) % 251) as u8)
            .collect()
    }

    #[test]
    fn accepts_valid_bao_slice_and_returns_exact_requested_bytes() {
        let data = sample_data();
        let (req, encoded) = fixture(&data, 7001..(60 * 1024 + 9));
        let verified = verify_bao_range(&req, &encoded).unwrap();

        assert_eq!(verified.manifest(), req.manifest);
        assert_eq!(verified.range(), &req.range);
        assert_eq!(verified.bytes(), &data[7001..(60 * 1024 + 9)]);
    }

    #[test]
    fn wrong_same_size_root_is_rejected() {
        let data = sample_data();
        let (mut req, encoded) = fixture(&data, 2000..24000);
        req.manifest.id = ContentId([42; 32]);
        assert!(matches!(
            verify_bao_range(&req, &encoded),
            Err(TransferError::CorruptData)
        ));
    }

    #[test]
    fn flipped_proof_bytes_are_rejected() {
        let data = sample_data();
        let (req, mut encoded) = fixture(&data, 2010..41000);
        let index = encoded.len() / 2;
        encoded[index] ^= 0x80;
        assert!(matches!(
            verify_bao_range(&req, &encoded),
            Err(TransferError::CorruptData)
        ));
    }

    #[test]
    fn truncated_and_trailing_bao_proofs_are_rejected() {
        let data = sample_data();
        let (req, encoded) = fixture(&data, 1001..40001);
        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(matches!(
            verify_bao_range(&req, &truncated),
            Err(TransferError::CorruptData)
        ));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            verify_bao_range(&req, &trailing),
            Err(TransferError::CorruptData)
        ));
    }

    #[test]
    fn tail_size_mismatch_or_empty_proof_cannot_mint_verified_bytes() {
        let data = sample_data();
        let end = data.len() as u64;
        // A partial interior proof is not a separate proof of TOTAL file
        // length: root+size must come from authorized manifest metadata.
        // Include the final leaf to test wrong-length rejection directly.
        let (mut req, encoded) = fixture(&data, end - 20000..end);
        assert!(matches!(
            verify_bao_range(&req, &[]),
            Err(TransferError::CorruptData)
        ));
        req.manifest.size += 1;
        assert!(matches!(
            verify_bao_range(&req, &encoded),
            Err(TransferError::CorruptData)
        ));
    }

    #[test]
    fn input_size_limit_applies_before_proof_parsing() {
        let data = sample_data();
        let (req, _) = fixture(&data, 20..12000);
        let excessive = vec![0_u8; MAX_BAO_PROOF_BYTES + 1];
        assert!(matches!(
            verify_bao_range(&req, &excessive),
            Err(TransferError::InvalidBudget)
        ));
    }

    #[test]
    fn authenticated_bao_range_enters_bounded_checkpoint() {
        use crate::planner::MissingRanges;

        let data = sample_data();
        let (request, encoded) = fixture(&data, 5000..14000);
        let verified = verify_bao_range(&request, &encoded).unwrap();
        let mut checkpoint = crate::planner::VerifiedCheckpoint::empty(request.manifest);
        assert_eq!(checkpoint.staged_ranges().count(), 0);
        checkpoint.record_bao(verified).unwrap();

        let recorded = checkpoint.staged_ranges().next().unwrap();
        assert_eq!(recorded.bytes(), &data[5000..14000]);
        assert_eq!(checkpoint.verified_ranges(), &[5000..14000]);

        let plan = MissingRanges::from_checkpoint(
            request.manifest,
            &checkpoint,
            crate::TransferBudget {
                max_inflight_bytes: 9000,
                max_sources: 1,
                max_retries: 0,
            },
        )
        .unwrap();

        let ranges = plan.map(|r| (r.start(), r.end())).collect::<Vec<_>>();
        assert_eq!(ranges[0], (0, 5000));
        assert_eq!(ranges[1], (14000, 23000));
        assert!(ranges.iter().all(|(s, e)| *e <= 5000 || *s >= 14000));
    }

    #[test]
    fn checkpoint_rejects_cryptographically_verified_other_root() {
        let data = sample_data();
        let (req, encoded) = fixture(&data, 1500..30000);
        let verified = verify_bao_range(&req, &encoded).unwrap();
        let different = Manifest {
            id: ContentId([97; 32]),
            size: req.manifest.size,
        };
        let mut checkpoint = crate::planner::VerifiedCheckpoint::empty(different);
        assert!(matches!(
            checkpoint.record_bao(verified),
            Err(TransferError::InvalidRange)
        ));
        assert!(checkpoint.verified_ranges().is_empty());
    }

    #[test]
    fn checkpoint_memory_limit_rejects_repeated_proofs_without_promotion() {
        const MIB: usize = 1024 * 1024;
        let data = vec![3u8; MIB + 64];
        let (req, encoded) = fixture(&data, 0..MIB as u64);
        let mut checkpoint = crate::planner::VerifiedCheckpoint::empty(req.manifest);

        for _ in 0..8 {
            let proof = verify_bao_range(&req, &encoded).unwrap();
            checkpoint.record_bao(proof).unwrap();
        }
        assert_eq!(checkpoint.staged_ranges().count(), 8);
        let ninth = verify_bao_range(&req, &encoded).unwrap();
        assert!(matches!(
            checkpoint.record_bao(ninth),
            Err(TransferError::InvalidBudget)
        ));
        assert_eq!(checkpoint.staged_ranges().count(), 8);
        assert_eq!(checkpoint.verified_ranges(), &[0..MIB as u64]);
    }

    #[test]
    fn huge_range_is_refused_even_before_parse() {
        let manifest = Manifest {
            id: ContentId([0; 32]),
            size: MAX_PLANNED_RANGE_BYTES + 1,
        };
        let req = TransferRequest::new(
            manifest,
            ByteRange::new(0, manifest.size, manifest.size).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_bao_range(&req, &[]),
            Err(TransferError::InvalidBudget)
        ));
    }
}
