# ADR-0002 — STY-G1b: fail-closed missing-range planning (laboratory)

Status: Draft, stacked above STY-G1 [PR #1](https://github.com/Lalalalendia/staya-transfer/pull/1).
Parent plan: [STY-MASTER-PLAN-02](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd).

## Goal

Produce a lazy, bounded list of missing byte ranges while refusing to mix checkpoints from another immutable object. The scheduler does not fetch bytes, authenticate remote peers, or verify a Bao proof.

## Security boundary

- VerifiedCheckpoint has private range storage bound to one full Manifest (BLAKE3 root plus length); public code can only create an EMPTY checkpoint. Calling MissingRanges::from_checkpoint with a different root or size fails closed.
- Only a future crate-internal cryptographic adapter will be permitted to mark ranges verified after checking their Bao proof against the exact root. There is NO public mark-verified API in this module.
- Tests inject synthetic authenticated intervals directly inside the module; this test-only access is not a production backend and must never be treated as such.
- Range geometry is checked independently. Malformed, overlapping, zero-length or out-of-bounds entries must not become skipped bytes.
- Each request is capped at 1 MiB, and ranges are yielded lazily, even for very large object lengths. A network decoder MUST separately enforce its byte/allocation limits.
- BLAKE3 verification of an entire object in STY-G1 does not prove arbitrary partial ranges. There is no crash-safe/persisted checkpoint here.
- Passing tests must not publish to an Akula vault, claim a remote peer is authorized, or mark a durable File Gate commit.

## Tests and acceptance

Tests cover missing-gap coverage, already-verified intervals, boundary splitting, empty and fully verified objects, invalid checkpoint length, same-size but wrong BLAKE3 identity, oversized/zero budgets, adjacent merges and u64 overflow edges.

Required before merging: exact-head Cargo fmt/test/clippy success (CI may remain queued); source/API review and upstream-backed authenticated range adapter remain future gates. No change to the public Akula sync engine.

## Next milestones

1. STY-G1c: use pinned iroh-blobs/Roha/noq with authenticated Bao range evidence and ensure ranges can only be promoted after proof verification.
2. STY-G2: explicit durable checkpoint/store lifecycle with competing-process/kill/restart tests.
3. STY-G3: Akula File Gate authorization and durable receipt in a separately gated integration.
