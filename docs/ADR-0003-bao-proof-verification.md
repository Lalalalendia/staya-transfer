# ADR-0003 — STY-G1c: Bao-verified in-memory range admission

Status: Draft, research-quality implementation; never claim production readiness or persisted resume.
Parent: [STY-MASTER-PLAN-02](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd), RN-4A.
Depends on stacked [PR #1](https://github.com/Lalalalendia/staya-transfer/pull/1) and [PR #2](https://github.com/Lalalalendia/staya-transfer/pull/2).

## Why this is needed

A BLAKE3 digest of a complete file does not authenticate arbitrary pieces of a partially downloaded file. The STY-G1 mock checked only complete objects, and the STY-G1b checkpoint deliberately rejected external byte claims. We need a specific cryptographic proof before skipping a missing range.

## Selected mechanism

- Use the synchronous Bao response verifier from bao-tree 0.16.1 with the 16 KiB block group configuration used in iroh-blobs 0.103.1. This validates each decoded leaf against the known full-object BLAKE3 root. Do not invent a second wire protocol.
- Pin the codec version in Cargo.toml and isolate the adapter behind feature flag bao. Cross-stack compatibility with the actual pinned fork remains unverified.
- The manifest BLAKE3 root and object size are trusted inputs supplied only after higher-level authorization. **A Bao proof for an interior subrange does not independently prove the complete object length.** Rejected metadata mismatches at the object tail are testable; length and identity must be fixed by trusted source metadata before accepting proofs. A peer can suggest data but not select a trusted root or access policy.
- Decode a single requested byte range. Require exact contiguous byte coverage, decode success, no trailing bytes, and matching full-object identity. Reject mismatched size, wrong root, corrupted proof, truncation or excessively large data.
- Bound requested output to 1 MiB, proof input to 2 MiB, and bytes retained in one in-memory checkpoint to 8 MiB. These limits are *in addition* to admission/transport/backpressure limits required by later adapters.
- VerifiedBaoRange has private fields, constructed only by proof decoding. VerifiedCheckpoint checks same manifest root and size before holding authenticated bytes and marking those intervals available for skip/resume planning. The checkpoint retains the bytes; it does not mark bytes present without retaining them.
- There is no durable checkpoint export, no unverified resume input, no disk write, and no claim of crash safety. A process restart invalidates all memory state and requires fresh proof or a future on-disk verifier.
- SHA of a pinned fork + all-features CI success, memory bounds and error tests are release requirements. The current GH Actions queue must finish before any claim that tests passed.

## Security test plan

Unit tests cover valid unaligned ranges, bad root of equal file size, flipped content/hash material, truncation, trailing bytes, inconsistent manifest size, empty proof, excessive proof/request sizes, checkpoint-to-manifest mismatch and 8 MiB retained-memory hard limit. The legitimate local producer constructs Bao proof fixtures with the same library; independent iroh-blobs wire E2E remains a separate gate.

## Next gates

1. Get exact-head cargo fmt, cargo test --all-features, clippy --all-features green; if compiler/API errors occur, fix them on this branch before merging.
2. Establish direct A/B with pinned Lalalalendia/iroh-blobs at immutable SHA, compare encoded byte ranges and proof validation with exact protocol version.
3. STY-G2: crash-safe partial store with verified metadata, atomic checkpoint root+size, single-writer ownership, forced SIGKILL and reopen tests. Do not accept an unverified interval map from disk as truth.
4. STY-G3: authorized cross-device Roha transfer with resource limits, then File Gate readback and durable revision ACK by Akula. Transport ACK is never an application receipt.

## Upstream evidence

- [iroh-blobs 0.103.1 get and proof handling](https://github.com/Lalalalendia/iroh-blobs/blob/main/src/get.rs)
- [bao-tree 0.16 verification API](https://docs.rs/bao-tree/0.16.1/bao_tree/io/sync/index.html)
- [STY-MASTER-PLAN-02](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd)

## Pinned compatibility observation (19 Oct 2026)

The inspected fork [Lalalalendia/iroh-blobs](https://github.com/Lalalalendia/iroh-blobs) at commit `a8f5b65d3e4ae0be7d9be7907458b9f1fd56aefa` resolves `bao-tree 0.16.1`, `iroh 1.3.0`, `noq 1.3.0` and `blake3 1.8.7`. Staya Transfer pins only `bao-tree 0.16.1` with a separate `blake3 1.8.5` contract and does not yet link the transport fork. The fork declares Rust 1.91 while this core crate declares 1.85. Exact-source Bao wire A/B and compiler-feature matrix are release gates, not completed validations.
