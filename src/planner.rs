//! Lazy missing-range scheduler for immutable byte objects.
//!
//! This only schedules reads. No peer authentication, Bao range proof,
//! network access, disk writes, or Akula File Gate changes occur here.
//!
//! SECURITY: input ranges MUST be authenticated externally against the same
//! immutable manifest. Never populate the ledger from untrusted peer inventory.
//! This constructor validates geometry, not cryptographic provenance.

use crate::{ByteRange, Manifest, TransferBudget, TransferError, VerifiedRanges};
use std::ops::Range;

/// Hard upper bound for an individual planned read.
pub const MAX_PLANNED_RANGE_BYTES: u64 = 1024 * 1024;

/// A checkpoint tied to one exact object identity.
/// External callers can only create an EMPTY checkpoint: verified ranges will
/// be inserted later by a crate-controlled cryptographic backend after proof
/// verification. In particular, peer-reported byte intervals are not trusted.
#[derive(Debug)]
pub struct VerifiedCheckpoint {
    manifest: Manifest,
    verified: VerifiedRanges,
}

impl VerifiedCheckpoint {
    pub fn empty(manifest: Manifest) -> Self {
        Self {
            manifest,
            verified: VerifiedRanges::default(),
        }
    }

    pub fn manifest(&self) -> Manifest {
        self.manifest
    }

    pub fn verified_ranges(&self) -> &[Range<u64>] {
        self.verified.ranges()
    }
}

/// Lazily produces missing intervals without proportional memory allocation.
#[derive(Debug)]
pub struct MissingRanges<'a> {
    manifest: Manifest,
    verified: &'a [Range<u64>],
    max_range_bytes: u64,
    cursor: u64,
    next_verified: usize,
}

impl<'a> MissingRanges<'a> {
    /// This validates the object's identity and interval geometry; it does
    /// not invent cryptographic proof. The checkpoint is never constructed
    /// from a peer-supplied list of allegedly verified ranges.
    pub fn from_checkpoint(
        manifest: Manifest,
        checkpoint: &'a VerifiedCheckpoint,
        budget: TransferBudget,
    ) -> Result<Self, TransferError> {
        if checkpoint.manifest != manifest {
            return Err(TransferError::InvalidRange);
        }
        let ranges = &checkpoint.verified;
        budget.validate()?;
        if budget.max_inflight_bytes > MAX_PLANNED_RANGE_BYTES {
            return Err(TransferError::InvalidBudget);
        }

        let mut previous_end = 0;
        for range in ranges.ranges() {
            if range.start >= range.end || range.end > manifest.size || range.start < previous_end {
                return Err(TransferError::InvalidRange);
            }
            previous_end = range.end;
        }

        Ok(Self {
            manifest,
            verified: ranges.ranges(),
            max_range_bytes: budget.max_inflight_bytes,
            cursor: 0,
            next_verified: 0,
        })
    }
}

impl Iterator for MissingRanges<'_> {
    type Item = ByteRange;

    fn next(&mut self) -> Option<Self::Item> {
        while self.cursor < self.manifest.size {
            while let Some(known) = self.verified.get(self.next_verified) {
                if self.cursor >= known.end {
                    self.next_verified += 1;
                } else if self.cursor >= known.start {
                    self.cursor = known.end;
                    self.next_verified += 1;
                } else {
                    break;
                }
            }

            if self.cursor >= self.manifest.size {
                return None;
            }

            let next_known_start = self
                .verified
                .get(self.next_verified)
                .map_or(self.manifest.size, |range| range.start);
            let end = self
                .cursor
                .saturating_add(self.max_range_bytes)
                .min(next_known_start)
                .min(self.manifest.size);

            if end == self.cursor {
                return None;
            }

            let planned = ByteRange::new(self.cursor, end, self.manifest.size).ok()?;
            self.cursor = end;
            return Some(planned);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContentId;

    fn manifest(size: u64) -> Manifest {
        Manifest {
            id: ContentId([4; 32]),
            size,
        }
    }

    fn budget(bytes: u64) -> TransferBudget {
        TransferBudget {
            max_inflight_bytes: bytes,
            max_sources: 1,
            max_retries: 0,
        }
    }

    fn pair(range: ByteRange) -> (u64, u64) {
        (range.start(), range.end())
    }

    #[test]
    fn empty_manifest_has_no_work() {
        let already = VerifiedCheckpoint::empty(manifest(0));
        let plan = MissingRanges::from_checkpoint(manifest(0), &already, budget(4)).unwrap();
        assert_eq!(plan.count(), 0);
    }

    #[test]
    fn splits_unverified_object_into_bounded_requests() {
        let already = VerifiedCheckpoint::empty(manifest(10));
        let plan = MissingRanges::from_checkpoint(manifest(10), &already, budget(3)).unwrap();
        assert_eq!(
            plan.map(pair).collect::<Vec<_>>(),
            [(0, 3), (3, 6), (6, 9), (9, 10)]
        );
    }

    #[test]
    fn skips_verified_spans_and_covers_each_missing_byte() {
        let mut already = VerifiedCheckpoint::empty(manifest(22));
        already
            .verified
            .add_verified(ByteRange::new(8, 12, 22).unwrap());
        already
            .verified
            .add_verified(ByteRange::new(0, 4, 22).unwrap());
        already
            .verified
            .add_verified(ByteRange::new(17, 22, 22).unwrap());
        let plan = MissingRanges::from_checkpoint(manifest(22), &already, budget(3)).unwrap();
        assert_eq!(
            plan.map(pair).collect::<Vec<_>>(),
            [(4, 7), (7, 8), (12, 15), (15, 17)]
        );
    }

    #[test]
    fn fully_verified_object_needs_no_download() {
        let mut already = VerifiedCheckpoint::empty(manifest(5));
        already
            .verified
            .add_verified(ByteRange::new(0, 5, 5).unwrap());
        let plan = MissingRanges::from_checkpoint(manifest(5), &already, budget(1)).unwrap();
        assert_eq!(plan.count(), 0);
    }

    #[test]
    fn rejects_checkpoint_from_different_content_length() {
        let mut stale = VerifiedCheckpoint::empty(manifest(15));
        stale
            .verified
            .add_verified(ByteRange::new(0, 15, 15).unwrap());
        assert!(matches!(
            MissingRanges::from_checkpoint(manifest(10), &stale, budget(2)),
            Err(TransferError::InvalidRange)
        ));
    }

    #[test]
    fn rejects_unbounded_or_zero_budget() {
        let already = VerifiedCheckpoint::empty(manifest(10));
        assert!(matches!(
            MissingRanges::from_checkpoint(manifest(10), &already, budget(0)),
            Err(TransferError::InvalidBudget)
        ));
        assert!(matches!(
            MissingRanges::from_checkpoint(
                manifest(10),
                &already,
                budget(MAX_PLANNED_RANGE_BYTES + 1)
            ),
            Err(TransferError::InvalidBudget)
        ));
    }

    #[test]
    fn near_u64_max_remains_lazy_without_overflow() {
        let mut already = VerifiedCheckpoint::empty(manifest(u64::MAX));
        already
            .verified
            .add_verified(ByteRange::new(0, u64::MAX - 10, u64::MAX).unwrap());
        let mut plan =
            MissingRanges::from_checkpoint(manifest(u64::MAX), &already, budget(1024)).unwrap();
        assert_eq!(plan.next().map(pair), Some((u64::MAX - 10, u64::MAX)));
        assert!(plan.next().is_none());
    }

    #[test]
    fn rejects_checkpoint_of_different_identity_even_with_same_size() {
        let checkpoint = VerifiedCheckpoint::empty(manifest(10));
        let other = Manifest {
            id: ContentId([5; 32]),
            size: 10,
        };
        assert!(matches!(
            MissingRanges::from_checkpoint(other, &checkpoint, budget(2)),
            Err(TransferError::InvalidRange)
        ));
    }

    #[test]
    fn adjacent_verified_spans_are_coalesced() {
        let mut already = VerifiedCheckpoint::empty(manifest(10));
        already
            .verified
            .add_verified(ByteRange::new(5, 8, 10).unwrap());
        already
            .verified
            .add_verified(ByteRange::new(2, 5, 10).unwrap());
        let plan = MissingRanges::from_checkpoint(manifest(10), &already, budget(4)).unwrap();
        assert_eq!(plan.map(pair).collect::<Vec<_>>(), [(0, 2), (8, 10)]);
    }
}
