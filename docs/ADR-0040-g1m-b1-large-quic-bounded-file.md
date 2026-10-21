# STY-G1m-b1 — First real >8 MiB Iroh QUIC transfer without whole-object application buffers

## Implemented lab-only vertical
Two explicit *new* commands on the accepted pinned Iroh release/fork manual direct preview, leaving existing `serve`/`receive` and `serve-batch`/`receive-batch` behavior and limits unchanged:

- `serve-large <synthetic-source> <explicit-receiver-id>`: only a regular non-symlink file strictly greater than 8 MiB and at most 16 MiB. Reject missing/invalid size **before any CONNECT invitation**. Open one OS source descriptor and validate metadata; Unix also compares pre-open and opened descriptor dev/inode. Independently BLAKE3-hash the already-open handle in 64 KiB blocks, rewind the same handle, copy with G1m-a `stream_to_uncommitted_quarantine` into one generated owner-private staging spool, fsync it, reopen and BLAKE3 re-audit the real spool. The permitted object is then imported via **pinned FsStore `add_path` in Copy mode**, not `add_slice(&full_file)`, and announced only after matching its returned hash to the chosen root.
- `receive-large`: a new ephemeral receiver identity; accepts the same manually authenticated one-object `CONNECT <ticket> <root> <size>` structure but **only** in the interval (8 MiB, 16 MiB]. One direct QUIC connection and finite G1i reconnect budget, 64 KiB bounded Bao GETs, actor/import admission. After clean FsStore shutdown, each physical 64 KiB persisted Bao range is *independently re-audited against the pinned full root* before being streamed to a generated private `large-verified-staged.bin` file. No full-file `Vec` for this receive path. After `sync_all`, the final file is independently reopened through a new descriptor, BLAKE3-verified via a 64 KiB buffer and only then gets the `STAGED ... NOT_APPLIED=true` diagnostic.

## Network/physical E2E acceptance gate
Linux and native Windows pinned Iroh release/fork:
- Real two OS processes, manually approved ephemeral recipient, deterministic synthetic **8 MiB +17 byte** source generated from a 64 KiB chunk; actual QUIC transfer and physical stage.
- Deny an unrelated QUIC receiver using the same invitation, without STAGED output.
- Cold independent on-disk readback through 64 KiB windows equals chosen BLAKE3 root and exact length; full file bytes and deterministic inventory are compared **byte for byte between release/fork**.
- Separate process refuses `16 MiB+1` declared local file before issuing a ticket. On Windows assert protected staging DACL and real anonymous-token data-read denial.
- Rustfmt/Clippy, existing one/batch-transfer tests, Docker and G2 worker/physical-fence CI remain intact.

## What this does **not** establish
- This first lab path is capped at **16 MiB for one object** and is **NOT** an increase in existing 8 MiB / 32 MiB selected multi-file queue limits. No 512 MiB network feature is being claimed.
- FsStore internals may allocate additional buffers, Bao metadata and a private copy; no formal bounded *whole-process* RAM claim or end-to-end throughput target without direct memory telemetry. Only the *application source hashing/spool read and cold receiver reconstruction* avoid entire-file `Vec`.
- `add_path` from an already verified private spool is a copied local FsStore import, not a direct native OS-handle ingestion API. Initial path open on Unix/Windows remains susceptible to insufficiently prevented attacker-controlled ancestor/reparse swaps; this command is **synthetic-only**.
- No signed Device/Vault grant, no Akula File Gate/APPLIED, no real durable power-loss resume, no production remote transport authorization, no automatic background queue/cancel, no relay/NAT support, no physical two-PC test [#51](https://github.com/Lalalalendia/staya-transfer/issues/51).
- If the process is killed during stage or copy, partial bytes may remain in a private directory; this is NOT a durable verified receipt. G2 release gate [#23](https://github.com/Lalalalendia/staya-transfer/issues/23) and supervisor [#26](https://github.com/Lalalalendia/staya-transfer/issues/26) remain OPEN.

## Next milestones
1. Verify real CI and fix observed failures on the exact HEAD, including strict Windows FsStore actor and byte comparison.
2. Generalize this path to stream more than one large object in an exact pinned queue without increasing aggregate memory; add explicit per-object disk reservations and stage cleanup on failure.
3. Extend to 32 MiB+17 and then larger sizes only after Linux and Windows real QUIC E2E, bounded outstanding requests, and physical post-write verification. Cross-process SIGKILL/resume and secure initial native file opens remain separate falsifiable gates.
