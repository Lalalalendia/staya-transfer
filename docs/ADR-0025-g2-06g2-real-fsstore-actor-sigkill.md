# ADR-0025 — STY-G2-06g2 real FsStore actor SIGKILL cut-points

Lab-only continuation of [G2-06 release matrix #23](https://github.com/Lalalalendia/staya-transfer/issues/23). Pinned release/fork `iroh-blobs::FsStore` is owned by a **separate Linux OS process** under an exclusive `StoreLease`; the parent never writes to its store. The parent observes an out-of-root test marker, confirms competing custody BUSY, kills with real SIGKILL (signal 9), waits for process death, and separately reacquires custody.

Four cuts: (1) independently authenticated Bao before FsStore import; (2) Bao partial import accepted by the live actor, no shutdown; (3) actor shut down and actual stored data/outboard independently verify against pinned BLAKE3 root but no published checkpoint; (4) actor shutdown + physical file/directory barriers + independent Bao verification + publication of one immutable checkpoint candidate, killed before any application acknowledgement.

At cuts 1–3, zero candidates and no retained-range authorization, even if bytes survived. At cut 4, the record is an untrusted candidate; independent root-anchored physical Bao re-audit is mandatory. Exact per-stage inventories are emitted as immutable CI artifacts and compared byte-for-byte between pinned release/fork.

Scope exclusions: this is SIGKILL, not power-loss; no interruption inside actor write or inside data/outboard fsync syscall, no physical ENOSPC, no hostile pathname swaps, no cross-platform Windows durable skip, no large many-range receipts, no production supervisor, no Akula File Gate or APPLIED. Keep G2-06 HOLD until all separate gates pass. No product code or installed Akula is modified.
