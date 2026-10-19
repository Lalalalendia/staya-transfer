//! STY-G1 bounded, in-memory mock source contract. No sockets or disk writes.
//!
//! The mock verifies a WHOLE immutable object using BLAKE3, deliberately not
//! individual Bao ranges. Production range verification and persisted resume
//! checkpoints belong to the selected pinned iroh-blobs backend. Passing these
//! tests is not evidence of direct/relay connectivity or safe Akula File Gate.

use crate::{ByteRange, ContentId, Manifest, TransferBudget, TransferError, TransferRequest};

/// Maximum object held by this laboratory runner, regardless of caller input.
pub const MAX_LAB_OBJECT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_LAB_INFLIGHT_BYTES: u64 = 1024 * 1024;
pub const MAX_LAB_SOURCES: usize = 16;
pub const MAX_LAB_RETRIES: u32 = 8;

/// Test double for an untrusted remote peer returning raw bytes.
/// Implementations MUST enforce the on-wire byte budget before allocation.
pub trait RangeSource {
    fn read_range(&mut self, request: &TransferRequest) -> Result<Vec<u8>, TransferError>;
}

/// Cancellation is checked before and after each bounded range request.
pub trait Cancellation {
    fn is_cancelled(&self) -> bool;
}

pub struct NeverCancel;

impl Cancellation for NeverCancel {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Constructed only after a complete BLAKE3 check against Manifest.id.
/// Still NOT a filesystem/durability receipt or application authorization.
#[derive(Debug)]
pub struct VerifiedObject {
    manifest: Manifest,
    bytes: Vec<u8>,
}

impl VerifiedObject {
    pub fn manifest(&self) -> Manifest {
        self.manifest
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Exercise strict transfer contracts with no network or external data access.
///
/// Only TransportUnavailable can be retried, at most max_retries additional
/// times per requested range. Incorrect lengths, authorization refusals,
/// integrity failure and cancellation always fail closed; incomplete bytes
/// never escape as VerifiedObject. This is NOT a restartable downloader.
pub fn fetch_complete<S: RangeSource, C: Cancellation>(
    manifest: Manifest,
    budget: TransferBudget,
    sources: &mut [S],
    cancel: &C,
) -> Result<VerifiedObject, TransferError> {
    budget.validate()?;
    if manifest.size == 0 || manifest.size > MAX_LAB_OBJECT_BYTES {
        return Err(TransferError::InvalidRange);
    }
    if budget.max_inflight_bytes > MAX_LAB_INFLIGHT_BYTES
        || budget.max_sources > MAX_LAB_SOURCES
        || budget.max_retries > MAX_LAB_RETRIES
    {
        return Err(TransferError::InvalidBudget);
    }
    if sources.is_empty() || sources.len() > budget.max_sources {
        return Err(TransferError::InvalidBudget);
    }
    let mut result = Vec::with_capacity(manifest.size as usize);
    let mut cursor = 0_u64;
    let mut next_source = 0_usize;
    while cursor < manifest.size {
        if cancel.is_cancelled() {
            return Err(TransferError::Cancelled);
        }
        let length = budget.max_inflight_bytes.min(manifest.size - cursor);
        let end = cursor + length;
        let range = ByteRange::new(cursor, end, manifest.size)?;
        let request = TransferRequest::new(manifest, range)?;
        let mut retries = 0_u32;
        loop {
            if cancel.is_cancelled() {
                return Err(TransferError::Cancelled);
            }
            let index = (next_source + retries as usize) % sources.len();
            match sources[index].read_range(&request) {
                Ok(bytes) => {
                    if bytes.len() as u64 != length {
                        return Err(TransferError::CorruptData);
                    }
                    result.extend_from_slice(&bytes);
                    break;
                }
                Err(TransferError::TransportUnavailable) if retries < budget.max_retries => {
                    retries += 1;
                }
                Err(TransferError::TransportUnavailable) => {
                    return Err(TransferError::ExhaustedBudget);
                }
                Err(other) => return Err(other),
            }
        }
        cursor = end;
        next_source = (next_source + 1) % sources.len();
    }
    if cancel.is_cancelled() {
        return Err(TransferError::Cancelled);
    }
    let actual = ContentId(*blake3::hash(&result).as_bytes());
    if actual != manifest.id {
        return Err(TransferError::CorruptData);
    }
    Ok(VerifiedObject {
        manifest,
        bytes: result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[derive(Clone)]
    struct MockSource {
        data: Vec<u8>,
        unavailable: usize,
        unauthorized: bool,
        poison: bool,
        trailing: bool,
        calls: usize,
    }

    impl MockSource {
        fn new(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                unavailable: 0,
                unauthorized: false,
                poison: false,
                trailing: false,
                calls: 0,
            }
        }
    }

    impl RangeSource for MockSource {
        fn read_range(&mut self, request: &TransferRequest) -> Result<Vec<u8>, TransferError> {
            self.calls += 1;
            if self.unauthorized {
                return Err(TransferError::Unauthorized);
            }
            if self.unavailable > 0 {
                self.unavailable -= 1;
                return Err(TransferError::TransportUnavailable);
            }
            let start = request.range.start() as usize;
            let end = request.range.end() as usize;
            let mut bytes = self.data[start..end].to_vec();
            if self.poison {
                bytes[0] ^= 0x80;
            }
            if self.trailing {
                bytes.push(0);
            }
            Ok(bytes)
        }
    }

    fn manifest(data: &[u8]) -> Manifest {
        Manifest {
            id: ContentId(*blake3::hash(data).as_bytes()),
            size: data.len() as u64,
        }
    }

    fn budget() -> TransferBudget {
        TransferBudget {
            max_inflight_bytes: 3,
            max_sources: 2,
            max_retries: 2,
        }
    }

    #[test]
    fn full_mock_transfer_only_returns_verified_complete_object() {
        let data = b"safe object bytes";
        let mut peers = [MockSource::new(data), MockSource::new(data)];
        let got = fetch_complete(manifest(data), budget(), &mut peers, &NeverCancel).unwrap();
        assert_eq!(got.bytes(), data);
        assert_eq!(got.manifest(), manifest(data));
        assert!(peers.iter().all(|p| p.calls > 0));
    }

    #[test]
    fn malicious_correct_length_content_is_rejected_by_root_digest() {
        let data = b"complete object";
        let mut source = [MockSource::new(data)];
        source[0].poison = true;
        let result = fetch_complete(manifest(data), budget(), &mut source, &NeverCancel);
        assert!(matches!(result, Err(TransferError::CorruptData)));
    }

    #[test]
    fn malicious_oversized_range_is_never_accepted() {
        let data = b"complete object";
        let mut source = [MockSource::new(data)];
        source[0].trailing = true;
        let result = fetch_complete(manifest(data), budget(), &mut source, &NeverCancel);
        assert!(matches!(result, Err(TransferError::CorruptData)));
        assert_eq!(source[0].calls, 1);
    }

    #[test]
    fn only_transport_unavailability_is_retried_within_budget() {
        let data = b"retry me";
        let mut peers = [MockSource::new(data), MockSource::new(data)];
        peers[0].unavailable = 1;
        assert!(fetch_complete(manifest(data), budget(), &mut peers, &NeverCancel).is_ok());
        assert!(peers[1].calls > 0);

        let mut offline = [MockSource::new(data)];
        offline[0].unavailable = 10;
        assert!(matches!(
            fetch_complete(manifest(data), budget(), &mut offline, &NeverCancel),
            Err(TransferError::ExhaustedBudget)
        ));
        assert_eq!(offline[0].calls, 3);
    }

    #[test]
    fn unauthorized_response_fails_immediately_without_retry() {
        let data = b"restricted object";
        let mut source = [MockSource::new(data)];
        source[0].unauthorized = true;
        assert!(matches!(
            fetch_complete(manifest(data), budget(), &mut source, &NeverCancel),
            Err(TransferError::Unauthorized)
        ));
        assert_eq!(source[0].calls, 1);
    }

    struct CancelAfter {
        checks: Cell<u32>,
        allowed: u32,
    }

    impl Cancellation for CancelAfter {
        fn is_cancelled(&self) -> bool {
            let seen = self.checks.get();
            self.checks.set(seen + 1);
            seen >= self.allowed
        }
    }

    #[test]
    fn cancellation_drops_unverified_partial_buffer() {
        let data = b"longer than one block";
        let mut source = [MockSource::new(data)];
        let cancel = CancelAfter {
            checks: Cell::new(0),
            allowed: 2,
        };
        assert!(matches!(
            fetch_complete(manifest(data), budget(), &mut source, &cancel),
            Err(TransferError::Cancelled)
        ));
        assert_eq!(source[0].calls, 1);
    }

    #[test]
    fn untrusted_manifest_and_resource_limits_fail_before_fetch() {
        let data = b"not read";
        let mut source = [MockSource::new(data)];
        let huge = Manifest {
            id: manifest(data).id,
            size: MAX_LAB_OBJECT_BYTES + 1,
        };
        assert!(matches!(
            fetch_complete(huge, budget(), &mut source, &NeverCancel),
            Err(TransferError::InvalidRange)
        ));
        let unbounded = TransferBudget {
            max_inflight_bytes: MAX_LAB_INFLIGHT_BYTES + 1,
            ..budget()
        };
        assert!(matches!(
            fetch_complete(manifest(data), unbounded, &mut source, &NeverCancel),
            Err(TransferError::InvalidBudget)
        ));
        let mut no_sources: [MockSource; 0] = [];
        assert!(matches!(
            fetch_complete(manifest(data), budget(), &mut no_sources, &NeverCancel),
            Err(TransferError::InvalidBudget)
        ));
        assert_eq!(source[0].calls, 0);
    }

    #[test]
    fn wrong_content_identity_cannot_be_satisfied_by_honest_peer() {
        let data = b"correct bytes";
        let wrong_id = ContentId([7; 32]);
        let mut source = [MockSource::new(data)];
        let result = fetch_complete(
            Manifest {
                id: wrong_id,
                size: data.len() as u64,
            },
            budget(),
            &mut source,
            &NeverCancel,
        );
        assert!(matches!(result, Err(TransferError::CorruptData)));
    }
}
