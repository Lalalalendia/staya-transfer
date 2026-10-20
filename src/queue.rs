//! G1k: bounded explicitly selected queue. No network, paths, File Gate,
//! durable proof, peer authorization or production Sync are claimed.
//! VerifiedStaged means bytes matched a pinned BLAKE3 root in memory only.

use crate::Manifest;
use std::collections::BTreeSet;

pub const MAX_QUEUE_FILES: usize = 8;
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_QUEUE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_LABEL_BYTES: usize = 64;
pub const MAX_RETRIES_PER_FILE: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedFile {
    /// A locally selected label; this must never be treated as a peer path.
    pub label: String,
    pub manifest: Manifest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueuePhase {
    Running,
    Paused,
    Held,
    Cancelled,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemOutcome {
    Pending,
    VerifiedStaged,
    Held,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    Empty,
    TooManyFiles,
    InvalidLabel,
    DuplicateLabel,
    DuplicateRoot,
    InvalidSize,
    TotalBytesExceeded,
    NotRunning,
    NotPaused,
    WrongManifest,
    UntrustedBytes,
    RetryLimit,
}

fn checked_label(label: &str) -> Result<String, QueueError> {
    if label.is_empty()
        || label.len() > MAX_LABEL_BYTES
        || !label.as_bytes()[0].is_ascii_alphanumeric()
        || !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        || label.ends_with('.')
    {
        return Err(QueueError::InvalidLabel);
    }
    let folded = label.to_ascii_lowercase();
    let stem = folded.split('.').next().unwrap_or_default();
    let reserved = matches!(stem, "con" | "prn" | "aux" | "nul")
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'));
    if reserved {
        return Err(QueueError::InvalidLabel);
    }
    Ok(folded)
}

/// Immutable local manifest sequence. Commitment is NOT an authorization token.
#[derive(Clone, Debug)]
pub struct QueueSelection {
    entries: Vec<SelectedFile>,
    total_bytes: u64,
    commitment: [u8; 32],
}

impl QueueSelection {
    pub fn new(entries: Vec<SelectedFile>) -> Result<Self, QueueError> {
        if entries.is_empty() {
            return Err(QueueError::Empty);
        }
        if entries.len() > MAX_QUEUE_FILES {
            return Err(QueueError::TooManyFiles);
        }
        let mut names = BTreeSet::new();
        let mut roots = BTreeSet::new();
        let mut total_bytes = 0u64;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"staya.ordered-queue.preview.v1\0");
        hasher.update(&(entries.len() as u64).to_le_bytes());
        for entry in &entries {
            let folded = checked_label(&entry.label)?;
            if !names.insert(folded) {
                return Err(QueueError::DuplicateLabel);
            }
            if entry.manifest.size == 0 || entry.manifest.size > MAX_FILE_BYTES {
                return Err(QueueError::InvalidSize);
            }
            if !roots.insert(entry.manifest.id.0) {
                return Err(QueueError::DuplicateRoot);
            }
            total_bytes = total_bytes
                .checked_add(entry.manifest.size)
                .ok_or(QueueError::TotalBytesExceeded)?;
            if total_bytes > MAX_QUEUE_BYTES {
                return Err(QueueError::TotalBytesExceeded);
            }
            hasher.update(&(entry.label.len() as u64).to_le_bytes());
            hasher.update(entry.label.as_bytes());
            hasher.update(&entry.manifest.id.0);
            hasher.update(&entry.manifest.size.to_le_bytes());
        }
        Ok(Self {
            entries,
            total_bytes,
            commitment: *hasher.finalize().as_bytes(),
        })
    }

    pub fn entries(&self) -> &[SelectedFile] {
        &self.entries
    }
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub fn into_cursor(self) -> QueueCursor {
        let outcomes = vec![ItemOutcome::Pending; self.entries.len()];
        QueueCursor {
            selection: self,
            outcomes,
            index: 0,
            retries: 0,
            phase: QueuePhase::Running,
        }
    }
}

/// Observable queue progress, based **only** on completely BLAKE3-verified
/// staged items. Never present this as network bytes, durable storage or
/// successfully APPLIED Akula revisions. Partial GETs and retries do not count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedStagingProgress {
    pub phase: QueuePhase,
    pub selected_items: usize,
    pub verified_staged_items: usize,
    pub selected_bytes: u64,
    pub verified_staged_bytes: u64,
}

impl VerifiedStagingProgress {
    pub fn remaining_items(&self) -> usize {
        self.selected_items - self.verified_staged_items
    }

    pub fn remaining_bytes(&self) -> u64 {
        self.selected_bytes - self.verified_staged_bytes
    }
}

/// Only verified locally pinned full-object bytes may advance this cursor.
/// A staged receipt cannot authorize network access or commit a user file.
#[derive(Debug)]
pub struct QueueCursor {
    selection: QueueSelection,
    outcomes: Vec<ItemOutcome>,
    index: usize,
    retries: u8,
    phase: QueuePhase,
}

impl QueueCursor {
    pub fn phase(&self) -> QueuePhase {
        self.phase
    }
    pub fn outcomes(&self) -> &[ItemOutcome] {
        &self.outcomes
    }
    pub fn selection(&self) -> &QueueSelection {
        &self.selection
    }
    pub fn current_index(&self) -> usize {
        self.index
    }
    pub fn retries_current(&self) -> u8 {
        self.retries
    }

    /// Derive from immutable selection + checked outcomes rather than
    /// trusting external receipts or speculative network ranges.
    pub fn verified_staging_progress(&self) -> VerifiedStagingProgress {
        let mut verified_staged_items = 0usize;
        let mut verified_staged_bytes = 0u64;
        for (item, outcome) in self.selection.entries.iter().zip(self.outcomes.iter()) {
            if *outcome == ItemOutcome::VerifiedStaged {
                verified_staged_items += 1;
                verified_staged_bytes += item.manifest.size;
            }
        }
        VerifiedStagingProgress {
            phase: self.phase,
            selected_items: self.selection.entries.len(),
            verified_staged_items,
            selected_bytes: self.selection.total_bytes,
            verified_staged_bytes,
        }
    }

    pub fn current(&self) -> Option<&SelectedFile> {
        (self.phase == QueuePhase::Running)
            .then(|| self.selection.entries.get(self.index))
            .flatten()
    }

    pub fn pause(&mut self) -> Result<(), QueueError> {
        if self.phase != QueuePhase::Running {
            return Err(QueueError::NotRunning);
        }
        self.phase = QueuePhase::Paused;
        Ok(())
    }
    pub fn resume(&mut self) -> Result<(), QueueError> {
        if self.phase != QueuePhase::Paused {
            return Err(QueueError::NotPaused);
        }
        self.phase = QueuePhase::Running;
        Ok(())
    }
    pub fn cancel(&mut self) -> Result<(), QueueError> {
        if !matches!(self.phase, QueuePhase::Running | QueuePhase::Paused) {
            return Err(QueueError::NotRunning);
        }
        self.outcomes[self.index] = ItemOutcome::Cancelled;
        self.phase = QueuePhase::Cancelled;
        Ok(())
    }

    /// Exactly two bounded retries after transport failures, never a skip.
    pub fn retry_transport_failure(&mut self) -> Result<(), QueueError> {
        if self.phase != QueuePhase::Running {
            return Err(QueueError::NotRunning);
        }
        if self.retries >= MAX_RETRIES_PER_FILE {
            self.hold_current();
            return Err(QueueError::RetryLimit);
        }
        self.retries += 1;
        Ok(())
    }

    /// Independent BLAKE3 check of complete bytes, not a durable receipt.
    pub fn record_verified_staging(
        &mut self,
        manifest: Manifest,
        staged: &[u8],
    ) -> Result<(), QueueError> {
        if self.phase != QueuePhase::Running {
            return Err(QueueError::NotRunning);
        }
        let expected = self.selection.entries[self.index].manifest;
        if manifest != expected {
            self.hold_current();
            return Err(QueueError::WrongManifest);
        }
        if staged.len() as u64 != expected.size || blake3::hash(staged).as_bytes() != &expected.id.0
        {
            self.hold_current();
            return Err(QueueError::UntrustedBytes);
        }
        self.outcomes[self.index] = ItemOutcome::VerifiedStaged;
        self.index += 1;
        self.retries = 0;
        if self.index == self.selection.entries.len() {
            self.phase = QueuePhase::Complete;
        }
        Ok(())
    }

    fn hold_current(&mut self) {
        self.phase = QueuePhase::Held;
        self.outcomes[self.index] = ItemOutcome::Held;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContentId;
    fn file(label: &str, bytes: &[u8]) -> SelectedFile {
        SelectedFile {
            label: label.into(),
            manifest: Manifest {
                id: ContentId(*blake3::hash(bytes).as_bytes()),
                size: bytes.len() as u64,
            },
        }
    }

    #[test]
    fn ordered_three_file_selection_cryptographically_verifies_every_object() {
        let tiny = vec![13];
        let boundary = vec![17; 64 * 1024];
        let large = vec![23; 1024 * 1024 + 17];
        let input = vec![
            file("tiny.bin", &tiny),
            file("boundary.bin", &boundary),
            file("large.bin", &large),
        ];
        let selection = QueueSelection::new(input.clone()).unwrap();
        assert_eq!(selection.total_bytes(), 1 + 65_536 + 1_048_593);
        let mut cursor = selection.into_cursor();
        for (i, payload) in [&tiny[..], &boundary[..], &large[..]].iter().enumerate() {
            assert_eq!(cursor.current_index(), i);
            assert_eq!(cursor.current().unwrap().label, input[i].label);
            cursor
                .record_verified_staging(input[i].manifest, payload)
                .unwrap();
            assert_eq!(cursor.outcomes()[i], ItemOutcome::VerifiedStaged);
        }
        assert_eq!(cursor.phase(), QueuePhase::Complete);
        assert!(cursor.current().is_none());
    }

    #[test]
    fn unsafe_windows_labels_and_duplicate_case_fold_are_rejected() {
        assert_eq!(QueueSelection::new(vec![]).err(), Some(QueueError::Empty));
        for label in [
            "",
            ".",
            "..",
            "a/../b",
            "a\\b",
            "C:temp",
            "trailing.",
            "with space",
            "CON",
            "con.txt",
            "PRN",
            "aux.txt",
            "nul",
            "COM1.bin",
            "LPT9.log",
            ".hidden",
        ] {
            assert_eq!(
                QueueSelection::new(vec![file(label, b"abc")]).err(),
                Some(QueueError::InvalidLabel),
                "{label}"
            );
        }
        assert_eq!(
            QueueSelection::new(vec![file(&"a".repeat(MAX_LABEL_BYTES + 1), b"x")]).err(),
            Some(QueueError::InvalidLabel)
        );
        assert_eq!(
            QueueSelection::new(vec![file("Book.epub", b"a"), file("book.EPUB", b"b")]).err(),
            Some(QueueError::DuplicateLabel)
        );
        assert_eq!(
            QueueSelection::new(vec![file("one", b"same"), file("two", b"same")]).err(),
            Some(QueueError::DuplicateRoot)
        );
    }

    #[test]
    fn hard_caps_count_size_and_total() {
        let excessive: Vec<_> = (0..=MAX_QUEUE_FILES)
            .map(|i| file(&format!("item{i}"), &[i as u8]))
            .collect();
        assert_eq!(
            QueueSelection::new(excessive).err(),
            Some(QueueError::TooManyFiles)
        );
        assert_eq!(
            QueueSelection::new(vec![file("empty", b"")]).err(),
            Some(QueueError::InvalidSize)
        );
        let oversize = SelectedFile {
            label: "huge".into(),
            manifest: Manifest {
                id: ContentId([7; 32]),
                size: MAX_FILE_BYTES + 1,
            },
        };
        assert_eq!(
            QueueSelection::new(vec![oversize]).err(),
            Some(QueueError::InvalidSize)
        );
        let many: Vec<_> = (0..5)
            .map(|i| SelectedFile {
                label: format!("large{i}"),
                manifest: Manifest {
                    id: ContentId([i as u8; 32]),
                    size: MAX_FILE_BYTES,
                },
            })
            .collect();
        assert_eq!(
            QueueSelection::new(many).err(),
            Some(QueueError::TotalBytesExceeded)
        );
    }

    #[test]
    fn only_original_root_can_advance_and_corruption_holds() {
        let first = file("first", b"abc");
        let other = file("other", b"def");
        let mut q = QueueSelection::new(vec![first.clone(), other.clone()])
            .unwrap()
            .into_cursor();
        assert_eq!(
            q.record_verified_staging(other.manifest, b"def"),
            Err(QueueError::WrongManifest)
        );
        assert_eq!(q.outcomes(), &[ItemOutcome::Held, ItemOutcome::Pending]);
        assert_eq!(q.current_index(), 0);
        assert_eq!(
            q.record_verified_staging(first.manifest, b"abc"),
            Err(QueueError::NotRunning)
        );
        let mut corrupt = QueueSelection::new(vec![first.clone()])
            .unwrap()
            .into_cursor();
        assert_eq!(
            corrupt.record_verified_staging(first.manifest, b"abd"),
            Err(QueueError::UntrustedBytes)
        );
        assert_eq!(corrupt.phase(), QueuePhase::Held);
        let mut short = QueueSelection::new(vec![first.clone()])
            .unwrap()
            .into_cursor();
        assert_eq!(
            short.record_verified_staging(first.manifest, b"ab"),
            Err(QueueError::UntrustedBytes)
        );
        assert_eq!(short.outcomes(), &[ItemOutcome::Held]);
    }

    #[test]
    fn order_changes_binding_and_pause_cancel_retry_never_skip() {
        let a = file("one", b"a");
        let b = file("two", b"b");
        let order_a = QueueSelection::new(vec![a.clone(), b.clone()]).unwrap();
        let order_b = QueueSelection::new(vec![b.clone(), a.clone()]).unwrap();
        assert_ne!(order_a.commitment(), order_b.commitment());
        let mut q = order_a.into_cursor();
        q.pause().unwrap();
        assert!(q.current().is_none());
        assert_eq!(
            q.record_verified_staging(a.manifest, b"a"),
            Err(QueueError::NotRunning)
        );
        q.resume().unwrap();
        q.retry_transport_failure().unwrap();
        q.retry_transport_failure().unwrap();
        assert_eq!(q.retry_transport_failure(), Err(QueueError::RetryLimit));
        assert_eq!(q.outcomes(), &[ItemOutcome::Held, ItemOutcome::Pending]);
        let mut q = order_b.into_cursor();
        q.record_verified_staging(b.manifest, b"b").unwrap();
        q.pause().unwrap();
        q.cancel().unwrap();
        assert_eq!(
            q.outcomes(),
            &[ItemOutcome::VerifiedStaged, ItemOutcome::Cancelled]
        );
        assert_eq!(q.retry_transport_failure(), Err(QueueError::NotRunning));
    }

    #[test]
    fn retry_budget_resets_only_after_authenticated_item() {
        let a = file("a", b"a");
        let b = file("b", b"b");
        let mut q = QueueSelection::new(vec![a.clone(), b.clone()])
            .unwrap()
            .into_cursor();
        q.retry_transport_failure().unwrap();
        q.retry_transport_failure().unwrap();
        q.record_verified_staging(a.manifest, b"a").unwrap();
        assert_eq!(q.retries_current(), 0);
        q.retry_transport_failure().unwrap();
        q.record_verified_staging(b.manifest, b"b").unwrap();
        assert_eq!(q.phase(), QueuePhase::Complete);
    }

    #[test]
    fn progress_is_only_verified_staged_bytes_and_never_speculative_transfer() {
        let a = file("a", b"a");
        let b = file("b", b"bb");
        let c = file("c", b"ccc");
        let mut q = QueueSelection::new(vec![a.clone(), b.clone(), c.clone()])
            .unwrap()
            .into_cursor();

        let start = q.verified_staging_progress();
        assert_eq!(start.phase, QueuePhase::Running);
        assert_eq!(start.selected_items, 3);
        assert_eq!(start.selected_bytes, 6);
        assert_eq!(start.verified_staged_items, 0);
        assert_eq!(start.verified_staged_bytes, 0);
        assert_eq!(start.remaining_items(), 3);
        assert_eq!(start.remaining_bytes(), 6);

        q.retry_transport_failure().unwrap();
        q.pause().unwrap();
        let paused = q.verified_staging_progress();
        assert_eq!(paused.phase, QueuePhase::Paused);
        assert_eq!(paused.verified_staged_bytes, 0);
        q.resume().unwrap();
        q.record_verified_staging(a.manifest, b"a").unwrap();

        let one = q.verified_staging_progress();
        assert_eq!(one.verified_staged_items, 1);
        assert_eq!(one.verified_staged_bytes, 1);
        assert_eq!(one.remaining_items(), 2);
        assert_eq!(one.remaining_bytes(), 5);
        assert_eq!(one.phase, QueuePhase::Running);

        // A remote "complete" event or corrupt bytes cannot inflate progress.
        assert_eq!(
            q.record_verified_staging(b.manifest, b"xx"),
            Err(QueueError::UntrustedBytes)
        );
        let held = q.verified_staging_progress();
        assert_eq!(held.phase, QueuePhase::Held);
        assert_eq!(held.verified_staged_items, 1);
        assert_eq!(held.verified_staged_bytes, 1);
        assert_eq!(held.remaining_bytes(), 5);
        assert_eq!(
            q.record_verified_staging(b.manifest, b"bb"),
            Err(QueueError::NotRunning)
        );
        assert_eq!(held, q.verified_staging_progress());

        let mut completed = QueueSelection::new(vec![a.clone(), b.clone()])
            .unwrap()
            .into_cursor();
        completed.record_verified_staging(a.manifest, b"a").unwrap();
        completed
            .record_verified_staging(b.manifest, b"bb")
            .unwrap();
        let done = completed.verified_staging_progress();
        assert_eq!(done.phase, QueuePhase::Complete);
        assert_eq!(done.verified_staged_items, 2);
        assert_eq!(done.verified_staged_bytes, 3);
        assert_eq!(done.remaining_items(), 0);
        assert_eq!(done.remaining_bytes(), 0);
    }

    #[test]
    fn cancellation_cannot_make_unverified_bytes_look_complete() {
        let a = file("a", b"a");
        let b = file("b", b"bb");
        let mut queue = QueueSelection::new(vec![a.clone(), b])
            .unwrap()
            .into_cursor();
        queue.record_verified_staging(a.manifest, b"a").unwrap();
        queue.pause().unwrap();
        queue.cancel().unwrap();
        let cancelled = queue.verified_staging_progress();
        assert_eq!(cancelled.phase, QueuePhase::Cancelled);
        assert_eq!(cancelled.verified_staged_items, 1);
        assert_eq!(cancelled.verified_staged_bytes, 1);
        assert_eq!(cancelled.remaining_bytes(), 2);
    }
}
