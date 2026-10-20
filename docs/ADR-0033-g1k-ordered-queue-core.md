# STY-G1k-a — Explicit bounded queue, **core contract only**

This slice implements [Issue #55](https://github.com/Lalalalendia/staya-transfer/issues/55)'s queue-control prerequisites without introducing a new service or misleadingly claiming actual multi-file QUIC transfer. It is a Rust 1.85 transport-neutral in-memory module in `src/queue.rs`, not a native file picker, sender/receiver, or Akula File Gate.

## Validated invariant
- Caller supplies an **explicit ordered** list of 1–8 local selected labels plus already-computed trusted BLAKE3 roots and exact nonzero lengths (max 8 MiB per item; 32 MiB per queue). Core keeps no physical paths, never enumerates folders or interprets peer-provided filenames.
- Labels are short ASCII alphanumeric/underscore/hyphen/period only, start alphanumeric, do not end with dot, case-insensitive duplicates rejected; reserved Windows device names and path syntax rejected. Same-root duplicate objects are rejected, preventing ambiguous replay in this deliberately narrow preview.
- Domain-separated deterministic queue binding includes count, label, exact size, BLAKE3 root, and order. **A hash of a selection is NOT a signature/authorization or a permission to query another peer.**
- A serial QueueCursor advances only after independently rehashing a supplied **complete** byte slice against the currently selected immutable root and size. Incorrect manifest/root, corrupted/truncated payload, and exhaustion fail closed in HOLD, with no advancement, no claimed durable receipt and no APPLIED/ACK.
- Pausing blocks staging; cancellation is terminal; at most two transport retries **per file** (never whole-list unbounded retries); budgets reset only after a cryptographically verified item.

## Tests
- Three synthetic different-sized items (1 byte / 64 KiB / 1 MiB +17) verify exact ordered receipt semantics.
- Wrong root, same-size corruption, truncation, duplicate case-folded labels, duplicate object roots, unsafe Windows labels, >8 selected, zero/oversized/over-total objects, order-dependent binding, pause/cancel, retry exhaustion, retry reset.
- Rust contracts run on original Rust 1.85 core without Iroh; existing pinned release/fork, Docker and native Windows CI must not regress.

## Required next implementation
- STY-G1k-b: an actual operator-selected multi-file QUIC **separate-process** preview with local physical regular-file checks, pinned per-file roots, one peer, explicit manifest and no unsolicited GET/PUSH. Add tests for denied extra roots, independent Bao+physical readback for all three objects and local ACL on Windows.
- STY-G1k-c: actual bounded cancel/pause and per-file statuses in the CLI; no mixing up network progress with disk durability.
- Do not use arbitrary queue labels for destination path construction. Stage under process-generated numbered names and independent private OS directory handles.
- Keep [G2-06 #23](https://github.com/Lalalalendia/staya-transfer/issues/23), supervisor [#26](https://github.com/Lalalalendia/staya-transfer/issues/26), and physical two-PC [#51](https://github.com/Lalalalendia/staya-transfer/issues/51) as independent HOLD gates.

**Never infer** current production multi-file transfer, Akula vault access, signed Device/Vault grants, fsync/power-loss durability, single-writer authority, WAN NAT connectivity, or File Gate permission from this core.
