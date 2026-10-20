# ADR-0024 — G2-06g1 real SIGKILL checkpoint metadata cut-points

Narrow Linux-only, **lab-only** follow-up to the [G2-06 acceptance matrix](https://github.com/Lalalalendia/staya-transfer/issues/23). Parent: G2-04a append-only metadata candidate publisher and G2-06c real FsStore SIGKILL + QUIC lab. This change DOES NOT modify Akula, File Gate, a network transfer, or production supervision.

## Falsifiable experiment

The non-default Cargo feature `g2-cutpoint-lab` adds observation hooks only at five exact `publish_candidate` stages: `record-written` (before file sync), `record-synced` (before rename), `renamed` (before directory sync), `directory-synced`, and `pre-ack`. The hook announces the stage to a marker **outside the custody root** and blocks; the parent uses real Linux `Child::kill` / SIGKILL and verifies exit signal 9. The publisher cannot execute a cooperative shutdown or return its metadata-barrier acknowledgement.

A **second OS process** acquires the same previously locked root and calls `read_candidates`. Before rename, no candidate is visible; after rename, exactly one syntactically valid *untrusted metadata candidate* may be visible. The test does not assume a pre-directory-sync rename survives actual power loss: SIGKILL does **not** emulate a power outage. A separate re-audit with absent physical Bao backings **must refuse** for every stage, even after directory sync.

CI: Linux custody workflow with `cargo test --locked --features g2-cutpoint-lab --test checkpoint_cutpoints` plus strict feature Clippy and global rustfmt. Windows compiles ordinary product code but does not claim Windows directory durability. The crash feature is **off by default** and never exercised by production builds.

## Strict exclusions / remaining G2-06 HOLD

This covers **metadata publisher** cut-points only, not FsStore actor partial-write/data-outboard sync, real Bao sidecar durability, >8 MiB multi-range receipts, physical ENOSPC, hostile writer races, recovery after power loss, Windows retained skip, production G2-05h3 supervisor, Akula File Gate, G3 or APPLIED. Merely finding a valid checkpoint file can NEVER authorize a skip. Exact-head Linux/Windows CI must pass before accepting this PR; the parent issue remains OPEN.
