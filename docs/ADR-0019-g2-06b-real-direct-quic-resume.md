# ADR-0019 — STY-G2-06b direct QUIC missing-only GET after CLEAN restart

**Scope:** narrow G2-06 lab evidence, stacked on [G2-06a PR #25](https://github.com/Lalalalendia/staya-transfer/pull/25), parent [G2-06 #23](https://github.com/Lalalalendia/staya-transfer/issues/23). Does NOT alter Akula or user documents.

## Experiment

1. The release/fork pinned real provider FsStore seeds a deterministic ~1 MiB object. An explicit secret-key-identified peer connects over actual direct QUIC with denied-by-default GET policy.
2. First GET receives real network proof for exactly one nontrivial interior aligned range `32768..196608`. A cooperative OS StoreLease, bounded in-flight ledger and pinned real receiver FsStore accept it through G2-05f's verified importer. The first connection and receiver actor cleanly close.
3. Independent physical `.data/.obao4` Bao audit against locally trusted immutable root and exact size is required; it must agree with freshly decoded first-wire Bao. Only then may an ephemeral VerifiedCheckpoint seed Staya's MissingRanges.
4. A **new QUIC connection** sends only two planned GET ranges: `0..32768` and `196608..object_size`. Both real network proofs are checked before importing into a freshly loaded receiver FsStore.
5. Real receiver FsStore returns the reassembled complete object, which is verified byte-for-byte and against the full locally trusted BLAKE3 root. It survives a further CLEAN actor shutdown/reopen.
6. The CI matrix runs pinned release/fork `--locked`, checks exact requested-range inventory, stores each raw GET proof and compares every proof byte-for-byte across variants.

## What this does NOT establish

- NOT a process kill/SIGKILL, process restart, OS fork-inherited lock proof, directory power-loss durability, stable checkpoint journal, or production-safe resumed skip; the first network proof remains available in test memory. G2-06a separately exercised cold verifier in a separate OS process.
- NOT relay, WAN, peer authorization from Akula grants, File Gate, final APPLIED receipt or user-visible synchronization.
- The partial importer still assumes quiescence and cooperative OS custody and does not enforce real physical disk quotas or safely stop a concurrently executing FsStore actor.
- The G2-06 seven-row release gate stays HOLD. [G2-05h2/#24](https://github.com/Lalalalendia/staya-transfer/pull/24), [G2-05h3a/#27](https://github.com/Lalalalendia/staya-transfer/pull/27), and Linux custody [#17](https://github.com/Lalalalendia/staya-transfer/pull/17) remain separate prerequisites.

**Acceptance for this PR only:** exact-head Rustfmt/Clippy, both pinned release/fork real QUIC + real FsStore tests, stable requested-range wire artefacts and full BLAKE3 match, existing CI retained.
