//! STY-G1l: bounded snapshot of an already-open regular-file descriptor.
//! This transfer code never follows a source pathname.
//! Caller must securely obtain the descriptor; a prior path-based File::open
//! is NOT made immune to symlink or ancestor substitution by this function.

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
};

use crate::{
    Manifest,
    queue::{QueueError, QueueSelection, SelectedFile},
};

#[derive(Debug)]
pub enum SourceSnapshotError {
    InvalidSelection(QueueError),
    NotRegularFile,
    OpenedFileSizeChanged,
    WrongPinnedRoot,
    Io(io::Error),
}

impl From<io::Error> for SourceSnapshotError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Complete bounded bytes from one OS descriptor. Neither an Akula grant
/// nor a proof that the original descriptor was obtained securely.
#[derive(Debug)]
pub struct SourceSnapshot {
    selected: SelectedFile,
    data: Vec<u8>,
}

impl SourceSnapshot {
    pub fn selected(&self) -> &SelectedFile {
        &self.selected
    }

    pub fn bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Consumes a pre-opened handle and checks exact size plus selected BLAKE3.
/// Later pathname replacement cannot redirect this already-open descriptor.
/// No path is accepted by this function, and only size + 1 bytes can be read.
pub fn snapshot_pinned_open_file(
    mut opened: File,
    selected: SelectedFile,
) -> Result<SourceSnapshot, SourceSnapshotError> {
    QueueSelection::new(vec![selected.clone()]).map_err(SourceSnapshotError::InvalidSelection)?;
    let expected: Manifest = selected.manifest;
    let initial = opened.metadata()?;
    if !initial.is_file() {
        return Err(SourceSnapshotError::NotRegularFile);
    }
    if initial.len() != expected.size {
        return Err(SourceSnapshotError::OpenedFileSizeChanged);
    }

    opened.seek(SeekFrom::Start(0))?;
    let mut data = Vec::with_capacity(expected.size as usize);
    {
        let mut bounded = opened.by_ref().take(expected.size + 1);
        bounded.read_to_end(&mut data)?;
    }

    let final_meta = opened.metadata()?;
    if !final_meta.is_file()
        || final_meta.len() != expected.size
        || data.len() as u64 != expected.size
    {
        return Err(SourceSnapshotError::OpenedFileSizeChanged);
    }
    if blake3::hash(&data).as_bytes() != &expected.id.0 {
        return Err(SourceSnapshotError::WrongPinnedRoot);
    }
    Ok(SourceSnapshot { selected, data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContentId;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct PrivateFixture(PathBuf);

    impl PrivateFixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "staya-pinned-source-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }

        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, bytes).unwrap();
            path
        }
    }

    impl Drop for PrivateFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn selected(label: &str, bytes: &[u8]) -> SelectedFile {
        SelectedFile {
            label: label.into(),
            manifest: Manifest {
                id: ContentId(*blake3::hash(bytes).as_bytes()),
                size: bytes.len() as u64,
            },
        }
    }

    #[test]
    fn authenticates_complete_bytes_from_open_file() {
        let root = PrivateFixture::new();
        let payload = vec![0x5a; 64 * 1024 + 17];
        let filename = root.file("selected.bin", &payload);
        let pinned = selected("selected.bin", &payload);
        let snap =
            snapshot_pinned_open_file(File::open(filename).unwrap(), pinned.clone()).unwrap();
        assert_eq!(snap.selected(), &pinned);
        assert_eq!(snap.bytes(), payload);
        assert_eq!(blake3::hash(snap.bytes()).as_bytes(), &pinned.manifest.id.0);
    }

    #[test]
    fn refuses_changed_bytes_same_length_and_shorter_or_longer_content() {
        let root = PrivateFixture::new();
        let filename = root.file("selected.bin", b"original");
        let manifest = selected("selected.bin", b"original");
        fs::write(&filename, b"tampered").unwrap();
        assert!(matches!(
            snapshot_pinned_open_file(File::open(&filename).unwrap(), manifest.clone()),
            Err(SourceSnapshotError::WrongPinnedRoot)
        ));
        fs::write(&filename, b"short").unwrap();
        assert!(matches!(
            snapshot_pinned_open_file(File::open(&filename).unwrap(), manifest.clone()),
            Err(SourceSnapshotError::OpenedFileSizeChanged)
        ));
        fs::write(&filename, b"original plus extra").unwrap();
        assert!(matches!(
            snapshot_pinned_open_file(File::open(&filename).unwrap(), manifest),
            Err(SourceSnapshotError::OpenedFileSizeChanged)
        ));
    }

    #[test]
    fn rejects_bad_label_and_nonregular_descriptor() {
        let root = PrivateFixture::new();
        let normal = root.file("source.bin", b"test");
        let bad = selected("../outside.bin", b"test");
        assert!(matches!(
            snapshot_pinned_open_file(File::open(&normal).unwrap(), bad),
            Err(SourceSnapshotError::InvalidSelection(
                QueueError::InvalidLabel
            ))
        ));
        #[cfg(unix)]
        {
            let manifest = selected("selected.bin", b"test");
            assert!(matches!(
                snapshot_pinned_open_file(File::open(&root.0).unwrap(), manifest),
                Err(SourceSnapshotError::NotRegularFile)
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn replacing_filename_after_open_cannot_swap_the_pinned_descriptor() {
        let root = PrivateFixture::new();
        let name = root.file("approved.bin", b"trusted");
        let original = selected("approved.bin", b"trusted");
        let opened = File::open(&name).unwrap();
        let renamed = root.0.join("old-inode.bin");
        fs::rename(&name, &renamed).unwrap();
        fs::write(&name, b"evil!!!").unwrap();
        let snap = snapshot_pinned_open_file(opened, original).unwrap();
        assert_eq!(snap.bytes(), b"trusted");
        assert_eq!(fs::read(name).unwrap(), b"evil!!!");
    }

    #[test]
    fn empty_or_oversized_selection_is_rejected_before_read() {
        let root = PrivateFixture::new();
        let name = root.file("small.bin", b"x");
        let empty = selected("empty.bin", b"");
        assert!(matches!(
            snapshot_pinned_open_file(File::open(&name).unwrap(), empty),
            Err(SourceSnapshotError::InvalidSelection(
                QueueError::InvalidSize
            ))
        ));
        let huge = SelectedFile {
            label: "huge.bin".into(),
            manifest: Manifest {
                id: ContentId([7; 32]),
                size: crate::queue::MAX_FILE_BYTES + 1,
            },
        };
        assert!(matches!(
            snapshot_pinned_open_file(File::open(&name).unwrap(), huge),
            Err(SourceSnapshotError::InvalidSelection(
                QueueError::InvalidSize
            ))
        ));
    }
}
