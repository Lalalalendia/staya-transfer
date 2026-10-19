#![forbid(unsafe_code)]
//! Transport-neutral transfer contracts for immutable, content-addressed data.
//!
//! This crate does not authenticate users, apply Akula revisions, or persist files.

use std::ops::Range;

/// A verified content identity, distinct from peer identity or Akula revision identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ContentId(pub [u8; 32]);

/// Declared content extent. The digest algorithm is part of a future negotiated profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub id: ContentId,
    pub size: u64,
}

/// A nonempty half-open byte interval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteRange(Range<u64>);

impl ByteRange {
    pub fn new(start: u64, end: u64, size: u64) -> Result<Self, TransferError> {
        if start >= end || end > size {
            return Err(TransferError::InvalidRange);
        }
        Ok(Self(start..end))
    }

    pub fn start(&self) -> u64 { self.0.start }
    pub fn end(&self) -> u64 { self.0.end }
    pub fn len(&self) -> u64 { self.0.end - self.0.start }
    pub fn is_empty(&self) -> bool { false }
}

/// Absolute resource limits for one transfer attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferBudget {
    pub max_inflight_bytes: u64,
    pub max_sources: usize,
    pub max_retries: u32,
}

impl TransferBudget {
    pub fn validate(&self) -> Result<(), TransferError> {
        if self.max_inflight_bytes == 0 || self.max_sources == 0 {
            return Err(TransferError::InvalidBudget);
        }
        Ok(())
    }
}

/// Idempotent scheduling request. Access policy is checked *before* producing this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferRequest {
    pub manifest: Manifest,
    pub range: ByteRange,
}

impl TransferRequest {
    pub fn new(manifest: Manifest, range: ByteRange) -> Result<Self, TransferError> {
        if range.end() > manifest.size { return Err(TransferError::InvalidRange); }
        Ok(Self { manifest, range })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferError {
    InvalidRange,
    InvalidBudget,
    Unauthorized,
    CorruptData,
    ExhaustedBudget,
    Cancelled,
    TransportUnavailable,
}

/// An exact range is complete only after an external digest verifier approves it.
/// This is a scheduling helper, not a substitute for Bao/BLAKE3 verification.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VerifiedRanges {
    ranges: Vec<Range<u64>>,
}

impl VerifiedRanges {
    pub fn add_verified(&mut self, verified: ByteRange) {
        self.ranges.push(verified.0);
        self.ranges.sort_by_key(|r| r.start);
        let mut merged: Vec<Range<u64>> = Vec::new();
        for r in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut() {
                if r.start <= last.end {
                    last.end = last.end.max(r.end);
                    continue;
                }
            }
            merged.push(r);
        }
        self.ranges = merged;
    }

    pub fn covers(&self, target: &ByteRange) -> bool {
        self.ranges.iter().any(|r| r.start <= target.start() && r.end >= target.end())
    }

    pub fn ranges(&self) -> &[Range<u64>] { &self.ranges }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_out_of_bounds_or_empty_ranges() {
        assert_eq!(ByteRange::new(1, 1, 10), Err(TransferError::InvalidRange));
        assert_eq!(ByteRange::new(3, 11, 10), Err(TransferError::InvalidRange));
        assert_eq!(ByteRange::new(9, 1, 10), Err(TransferError::InvalidRange));
        assert_eq!(ByteRange::new(0, 0, 0), Err(TransferError::InvalidRange));
    }

    #[test]
    fn validates_budgets() {
        assert_eq!(TransferBudget { max_inflight_bytes: 0, max_sources: 1, max_retries: 0 }.validate(), Err(TransferError::InvalidBudget));
        assert_eq!(TransferBudget { max_inflight_bytes: 1, max_sources: 0, max_retries: 1 }.validate(), Err(TransferError::InvalidBudget));
        assert!(TransferBudget { max_inflight_bytes: 1, max_sources: 1, max_retries: 0 }.validate().is_ok());
    }

    #[test]
    fn merges_only_adjacent_or_overlapping_verified_intervals() {
        let mut v = VerifiedRanges::default();
        v.add_verified(ByteRange::new(4, 8, 20).unwrap());
        v.add_verified(ByteRange::new(0, 4, 20).unwrap());
        v.add_verified(ByteRange::new(10, 12, 20).unwrap());
        assert_eq!(v.ranges(), &[0..8, 10..12]);
        assert!(v.covers(&ByteRange::new(1, 8, 20).unwrap()));
        assert!(!v.covers(&ByteRange::new(8, 10, 20).unwrap()));
    }

    #[test]
    fn request_rejects_range_beyond_manifest_even_if_individually_valid() {
        let m = Manifest { id: ContentId([0; 32]), size: 3 };
        let r = ByteRange::new(0, 4, 4).unwrap();
        assert_eq!(TransferRequest::new(m, r), Err(TransferError::InvalidRange));
    }
}
