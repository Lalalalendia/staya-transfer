//! Constant-buffer staging of large objects under a pinned BLAKE3 root.
//! The destination MUST be private, disposable, and UNCOMMITTED. Bytes
//! written before final authentication are untrusted; every error demands
//! quarantine cleanup. This is not durable or a QUIC/Bao range receipt.

use std::{
    io::{self, Read, Write},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{ContentId, Manifest};

pub const STREAM_BUFFER_BYTES: usize = 64 * 1024;
pub const MAX_STREAM_OBJECT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug)]
pub enum StreamStageError {
    InvalidSize,
    Cancelled,
    ShortRead { expected: u64, received: u64 },
    ExcessInput,
    RootMismatch,
    SourceIo(io::Error),
    StagingIo(io::Error),
}

/// Whole-input authentication only. No proof of actual staged-file readback,
/// fsync/power-loss durability, remote authorization or Akula application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct RootVerifiedQuarantineCopy {
    pub root: ContentId,
    pub bytes: u64,
    pub read_calls: u64,
    pub max_requested_read_bytes: usize,
}

/// Copies at most 512 MiB using a fixed 64 KiB buffer, no pathname lookup.
/// NEVER pass a publicly visible or user-vault destination as quarantine.
/// Quarantine can contain untrusted partial data before a final root check.
/// On failure the caller MUST discard it, not publish it or create an ACK.
pub fn stream_to_uncommitted_quarantine<R: Read, W: Write>(
    source: &mut R,
    quarantine: &mut W,
    expected: Manifest,
    cancelled: &AtomicBool,
) -> Result<RootVerifiedQuarantineCopy, StreamStageError> {
    if expected.size == 0 || expected.size > MAX_STREAM_OBJECT_BYTES {
        return Err(StreamStageError::InvalidSize);
    }
    let mut buffer = [0u8; STREAM_BUFFER_BYTES];
    let mut hasher = blake3::Hasher::new();
    let mut received = 0u64;
    let mut calls = 0u64;
    let mut max_requested_read_bytes = 0usize;
    while received < expected.size {
        if cancelled.load(Ordering::Acquire) {
            return Err(StreamStageError::Cancelled);
        }
        let ask = ((expected.size - received) as usize).min(STREAM_BUFFER_BYTES);
        max_requested_read_bytes = max_requested_read_bytes.max(ask);
        let count = loop {
            match source.read(&mut buffer[..ask]) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(StreamStageError::SourceIo(e)),
                Ok(n) => break n,
            }
        };
        calls += 1;
        if count == 0 {
            return Err(StreamStageError::ShortRead {
                expected: expected.size,
                received,
            });
        }
        // A failed/partial write NEVER yields an authentication receipt.
        quarantine
            .write_all(&buffer[..count])
            .map_err(StreamStageError::StagingIo)?;
        hasher.update(&buffer[..count]);
        received += count as u64;
    }
    if cancelled.load(Ordering::Acquire) {
        return Err(StreamStageError::Cancelled);
    }
    // One-byte EOF probe rejects a deceptive oversized source without
    // buffering any of the unexpected data.
    let mut trailing = [0u8; 1];
    loop {
        match source.read(&mut trailing) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(StreamStageError::SourceIo(e)),
            Ok(0) => break,
            Ok(_) => return Err(StreamStageError::ExcessInput),
        }
    }
    if hasher.finalize().as_bytes() != &expected.id.0 {
        return Err(StreamStageError::RootMismatch);
    }
    // Flush is not a durable fsync and does not authorize publication.
    quarantine.flush().map_err(StreamStageError::StagingIo)?;
    Ok(RootVerifiedQuarantineCopy {
        root: expected.id,
        bytes: received,
        read_calls: calls,
        max_requested_read_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PatternReader {
        size: u64,
        offset: u64,
        interrupt_once: bool,
    }

    impl PatternReader {
        fn new(size: u64) -> Self {
            Self { size, offset: 0, interrupt_once: false }
        }
        fn value(i: u64) -> u8 {
            (i.wrapping_mul(37).wrapping_add(19) % 251) as u8
        }
    }

    impl Read for PatternReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(buf.len() <= STREAM_BUFFER_BYTES);
            if self.interrupt_once {
                self.interrupt_once = false;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            if self.offset == self.size {
                return Ok(0);
            }
            let n = ((self.size - self.offset) as usize).min(buf.len());
            for (j, x) in buf[..n].iter_mut().enumerate() {
                *x = Self::value(self.offset + j as u64);
            }
            self.offset += n as u64;
            Ok(n)
        }
    }

    fn selected(size: u64) -> Manifest {
        let mut source = PatternReader::new(size);
        let mut h = blake3::Hasher::new();
        let mut b = [0u8; STREAM_BUFFER_BYTES];
        loop {
            let n = source.read(&mut b).unwrap();
            if n == 0 {
                break;
            }
            h.update(&b[..n]);
        }
        Manifest { id: ContentId(*h.finalize().as_bytes()), size }
    }

    #[test]
    fn thirty_two_mib_stream_plus_tail_with_bounded_fixed_buffer() {
        let n = 32 * 1024 * 1024 + 17;
        let mut source = PatternReader::new(n);
        let mut stage = io::sink();
        let manifest = selected(n);
        let receipt = stream_to_uncommitted_quarantine(
            &mut source, &mut stage, manifest, &AtomicBool::new(false),
        ).unwrap();
        assert_eq!(receipt.root, manifest.id);
        assert_eq!(receipt.bytes, n);
        assert!(receipt.read_calls > 500);
        assert_eq!(receipt.max_requested_read_bytes, STREAM_BUFFER_BYTES);
        assert_eq!(source.offset, n);
    }

    #[test]
    fn interrupted_read_retries_without_reusing_unverified_progress() {
        let n = STREAM_BUFFER_BYTES as u64 + 3;
        let mut source = PatternReader::new(n);
        source.interrupt_once = true;
        let mut stage = io::sink();
        let r = stream_to_uncommitted_quarantine(
            &mut source, &mut stage, selected(n), &AtomicBool::new(false),
        ).unwrap();
        assert_eq!(r.read_calls, 2);
        assert_eq!(r.bytes, n);
    }

    #[test]
    fn same_size_tamper_fails_even_if_uncommitted_staging_has_bytes() {
        let mut source = io::Cursor::new(vec![0xa5; 257]);
        let mut stage = Vec::new();
        assert!(matches!(
            stream_to_uncommitted_quarantine(
                &mut source, &mut stage, selected(257), &AtomicBool::new(false)
            ),
            Err(StreamStageError::RootMismatch)
        ));
        assert_eq!(stage.len(), 257);
    }

    #[test]
    fn truncated_and_excess_files_never_return_a_receipt() {
        let wanted = selected(8);
        let mut stage = Vec::new();
        let mut shorter = io::Cursor::new(vec![1; 7]);
        assert!(matches!(
            stream_to_uncommitted_quarantine(
                &mut shorter, &mut stage, wanted, &AtomicBool::new(false)
            ),
            Err(StreamStageError::ShortRead { expected: 8, received: 7 })
        ));
        stage.clear();
        let mut excess = io::Cursor::new(vec![1; 9]);
        assert!(matches!(
            stream_to_uncommitted_quarantine(
                &mut excess, &mut stage, wanted, &AtomicBool::new(false)
            ),
            Err(StreamStageError::ExcessInput)
        ));
        assert_eq!(excess.position(), 9);
    }

    struct FullDisk { available: usize }
    impl Write for FullDisk {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.available == 0 {
                return Err(io::Error::other("synthetic disk full"));
            }
            let n = self.available.min(bytes.len());
            self.available -= n;
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }

    #[test]
    fn disk_full_is_fail_closed() {
        let n = 65536;
        let mut source = PatternReader::new(n);
        let mut stage = FullDisk { available: 100 };
        assert!(matches!(
            stream_to_uncommitted_quarantine(
                &mut source, &mut stage, selected(n), &AtomicBool::new(false)
            ),
            Err(StreamStageError::StagingIo(_))
        ));
    }

    #[test]
    fn cancellation_does_not_promote_any_partial_output() {
        let n = 65536;
        let mut source = PatternReader::new(n);
        let mut stage = Vec::new();
        assert!(matches!(
            stream_to_uncommitted_quarantine(
                &mut source, &mut stage, selected(n), &AtomicBool::new(true)
            ),
            Err(StreamStageError::Cancelled)
        ));
        assert!(stage.is_empty());
    }

    struct NoRead;
    impl Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("must reject invalid manifest before source IO")
        }
    }

    #[test]
    fn zero_and_over_cap_are_rejected_before_read() {
        let mut source = NoRead;
        let mut stage = io::sink();
        for n in [0, MAX_STREAM_OBJECT_BYTES + 1] {
            assert!(matches!(
                stream_to_uncommitted_quarantine(
                    &mut source,
                    &mut stage,
                    Manifest { id: ContentId([0; 32]), size: n },
                    &AtomicBool::new(false)
                ),
                Err(StreamStageError::InvalidSize)
            ));
        }
    }
}
