//! Fail-closed STY-G2 recovery *policy*, not a persistent store.
//!
//! This module has no filesystem, locking, network or Akula write authority.
//! In particular, reading a checkpoint cannot by itself mark ranges verified.
//! The future FsStore adapter must independently authenticate bytes and Bao
//! outboard after restart before the scheduler is allowed to skip any range.

use crate::Manifest;

/// Exact on-disk Bao encoding expected by the pinned iroh-blobs experiment.
/// Unsupported profiles can be read from untrusted metadata but never resumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaoStorageProfile {
    IrohBlobs0103PreOrder16KiB,
    Unsupported(u32),
}

/// The identity required to match for every persisted partial checkpoint.
/// A BLAKE3 root without exact length and encoding profile is insufficient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreIdentity {
    pub manifest: Manifest,
    pub profile: BaoStorageProfile,
}

/// Observations supplied by a future exclusive-owner filesystem adapter.
///
/// No variant is proof of a durable fsync, exclusive writer, or valid Bao data.
/// In particular, PublishedCheckpoint is only a claim from persisted metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReopenObservation {
    /// The owner has independently established a new *empty, private* area.
    FreshPrivateStore,
    PublishedCheckpoint(StoreIdentity),
    /// A prior write/barrier/rename could have been interrupted.
    IncompleteCheckpoint,
    CorruptCheckpoint,
    MissingData,
    MissingOutboard,
    WriterAlreadyActive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryFault {
    UnsupportedProfile,
    DifferentObject,
    IncompleteCheckpoint,
    CorruptCheckpoint,
    MissingData,
    MissingOutboard,
    WriterAlreadyActive,
}

/// Safe next step; intentionally contains NO "resume" or "skip" state.
///
/// The future adapter must do fresh physical Bao verification and exclusive
/// store ownership checks before authorizing any recovered range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReopenAction {
    InitializePrivateStaging,
    AuditPhysicalDataAndBao,
    Hold(RecoveryFault),
}

/// Classify a restart without trusting checkpoint bits or observed filenames.
///
/// This pure function performs NO disk access and NEVER permits skipped bytes.
/// Its caller must have authenticated the expected manifest independently.
pub fn decide_reopen(
    expected: StoreIdentity,
    observed: ReopenObservation,
) -> ReopenAction {
    use BaoStorageProfile::IrohBlobs0103PreOrder16KiB as Supported;
    use ReopenAction::{AuditPhysicalDataAndBao, Hold, InitializePrivateStaging};
    use ReopenObservation::{
        CorruptCheckpoint, FreshPrivateStore, IncompleteCheckpoint, MissingData,
        MissingOutboard, PublishedCheckpoint, WriterAlreadyActive,
    };
    use RecoveryFault as Fault;

    if expected.profile != Supported {
        return Hold(Fault::UnsupportedProfile);
    }

    match observed {
        FreshPrivateStore => InitializePrivateStaging,
        PublishedCheckpoint(actual) if actual.profile != Supported => {
            Hold(Fault::UnsupportedProfile)
        }
        PublishedCheckpoint(actual) if actual != expected => Hold(Fault::DifferentObject),
        PublishedCheckpoint(_) => AuditPhysicalDataAndBao,
        IncompleteCheckpoint => Hold(Fault::IncompleteCheckpoint),
        CorruptCheckpoint => Hold(Fault::CorruptCheckpoint),
        MissingData => Hold(Fault::MissingData),
        MissingOutboard => Hold(Fault::MissingOutboard),
        WriterAlreadyActive => Hold(Fault::WriterAlreadyActive),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContentId;

    fn identity(root: u8, size: u64) -> StoreIdentity {
        StoreIdentity {
            manifest: Manifest {
                id: ContentId([root; 32]),
                size,
            },
            profile: BaoStorageProfile::IrohBlobs0103PreOrder16KiB,
        }
    }

    #[test]
    fn matching_published_record_requires_physical_audit_before_reuse() {
        let expected = identity(7, 4096);
        assert_eq!(
            decide_reopen(expected, ReopenObservation::PublishedCheckpoint(expected)),
            ReopenAction::AuditPhysicalDataAndBao
        );
    }

    #[test]
    fn different_root_or_exact_size_cannot_be_reused() {
        let expected = identity(7, 4096);
        for wrong in [identity(8, 4096), identity(7, 4097)] {
            assert_eq!(
                decide_reopen(expected, ReopenObservation::PublishedCheckpoint(wrong)),
                ReopenAction::Hold(RecoveryFault::DifferentObject)
            );
        }
    }

    #[test]
    fn unknown_on_disk_profile_and_unknown_expected_profile_hold() {
        let expected = identity(7, 4096);
        let mut recorded = expected;
        recorded.profile = BaoStorageProfile::Unsupported(18);
        assert_eq!(
            decide_reopen(expected, ReopenObservation::PublishedCheckpoint(recorded)),
            ReopenAction::Hold(RecoveryFault::UnsupportedProfile)
        );
        assert_eq!(
            decide_reopen(recorded, ReopenObservation::FreshPrivateStore),
            ReopenAction::Hold(RecoveryFault::UnsupportedProfile)
        );
    }

    #[test]
    fn interrupted_or_corrupted_records_never_become_verified_ranges() {
        let expected = identity(7, 4096);
        for (observation, fault) in [
            (ReopenObservation::IncompleteCheckpoint, RecoveryFault::IncompleteCheckpoint),
            (ReopenObservation::CorruptCheckpoint, RecoveryFault::CorruptCheckpoint),
            (ReopenObservation::MissingData, RecoveryFault::MissingData),
            (ReopenObservation::MissingOutboard, RecoveryFault::MissingOutboard),
            (ReopenObservation::WriterAlreadyActive, RecoveryFault::WriterAlreadyActive),
        ] {
            assert_eq!(
                decide_reopen(expected, observation),
                ReopenAction::Hold(fault)
            );
        }
    }

    #[test]
    fn genuinely_fresh_private_area_only_permits_initialization() {
        assert_eq!(
            decide_reopen(identity(7, 4096), ReopenObservation::FreshPrivateStore),
            ReopenAction::InitializePrivateStaging
        );
    }
}
