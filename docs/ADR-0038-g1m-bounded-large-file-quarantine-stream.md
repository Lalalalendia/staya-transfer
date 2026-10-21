# STY-G1m-a — constant-memory full-root streaming to uncommitted quarantine

## Purpose and scope
The accepted G1k single/batch laboratory preview uses a maximum 8 MiB file size with whole-object memory buffering and limits an eight-object queue to 32 MiB. That is insufficient for arbitrary Akula file transfer. This slice adds a transport-neutral, independent primitive to copy and authenticate a substantially larger **selected stream without growing memory with file size**. It is intentionally not yet integrated with Iroh QUIC or user vaults.

## Implementation
- `src/source_stream.rs`: `stream_to_uncommitted_quarantine(source: &mut impl Read, quarantine: &mut impl Write, expected: Manifest, cancel: &AtomicBool)`.
- Hard 64 KiB stack buffer per call, at most 512 MiB input object, no filesystem path lookup, no `Vec` of entire source data. Reads exactly declared length in bounded chunks and probes **one extra byte** to refuse oversized or unstable sources without buffering trailing bytes.
- Builds one incremental BLAKE3 hash and compares to the caller's independently pinned complete root. Returns `RootVerifiedQuarantineCopy` only on exact size + root, successful staging writes, and flush; read/short/excess/root mismatch/ENOSPC/cancellation return error and NO verified receipt.
- No receipt of partial bytes, no remote ACK, no Bao range verification, no durable checkpoint, no writer fence, no fsync or Akula File Gate.
- Caller MUST provide a separately owned **private uncommitted staging destination** and destroy its contents on any error. The staging writer can contain untrusted bytes before final-root verification. Even after the streaming receipt, the actual physical output needs a separate cold file readback / Bao and disk-durability validation before higher trust.
- Existing G1k-a queue limit (8 MiB/file, 32 MiB total) deliberately unchanged. This stream limit is a new laboratory primitive, not yet permission to send 512 MiB over QUIC.

## Acceptance on one physical machine
- Synthetic deterministic 32 MiB +17 stream read in fixed 64 KiB requests with a discard sink, proving no complete-file `Vec` is allocated in this primitive.
- Odd size, interrupted read, same-size malicious tampering, truncation, excess byte, ENOSPC during partial staging, cancellation and 0 or 512 MiB+1 declared size refused.
- Rust 1.85 contracts and pinned release/fork plus native Windows compatibility CI on exact PR HEAD. No two-PC hardware required.

## Follow-up G1m-b (separate gate)
- Use secure initial OS file handles and real private bounded spool files for sources; never publish a partial spool.
- Replace G1k-c whole-object `FsStore::add_slice` seeding with an actual incremental pinned Iroh FsStore ingress adapter, in release and fork variants, not an invented API assumption. Demand physical independent Bao/BLAKE3 readback for 32 MiB+17 and controlled source modifications before permit.
- Add fixed outstanding GET-range admission, cancellation and disk limits, bounded QUIC backpressure, crash cleanup, and Linux/Windows byte-for-byte tests. Only then raise the preview file limits.
- Durable resume, Windows native owner identity, signed Device/Vault grants and Akula File Gate remain governed by independent [G2 #23](https://github.com/Lalalalendia/staya-transfer/issues/23), [supervisor #26](https://github.com/Lalalalendia/staya-transfer/issues/26) and hardware [#51](https://github.com/Lalalalendia/staya-transfer/issues/51).

Implementation follows existing [queue #55](https://github.com/Lalalalendia/staya-transfer/issues/55), [source handle PR #71](https://github.com/Lalalalendia/staya-transfer/pull/71), and [single-session PR #67](https://github.com/Lalalalendia/staya-transfer/pull/67). Do not describe this primitive as network transfer, a production memory guarantee for other components or a completed 512 MiB end-user feature.
