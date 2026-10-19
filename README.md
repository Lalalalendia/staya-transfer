# Staya Transfer

Transport-independent, resumable and bounded transfer of content-addressed
byte objects for the Staya network. This repository is a standalone Rust
library, **not a deployed sync service**.

## Component boundaries

- `noq` provides QUIC stream and packet behavior.
- `roha` provides authenticated peer connectivity, discovery, NAT traversal,
  relay routing and network limits.
- This repository owns the **transfer contract**: immutable content manifests,
  bounded scheduling, sources, cancellation and verification outcomes.
- `iroh-blobs` is the preferred Bao/BLAKE3 transfer and resumable store
  backend; its source remains external and is not vendored here.
- `WOW` sends separately authorized small envelopes and receipts.
- **Akula alone** owns user/device ACL, revision DAG, File Gate, conflicts,
  history and durable application. A QUIC ACK or BLAKE3 match NEVER permits
  modifying a user document.

## STY-G1 status

- Base contracts: `Manifest`, `ContentId`, `ByteRange`, `TransferBudget`.
- `lab::fetch_complete`: bounded in-memory mock with whole-object BLAKE3,
  limited source attempts and cancellation. Bad or incomplete bytes are never
  published as a verified object.
- All network and filesystem interactions are **intentionally absent**.
- This is not a working P2P transfer, persistent resume, or safe Akula sync.
- See [ADR-0001](docs/ADR-0001-sty-g1-boundaries.md) for risks and next gates.

## Development

Rust 1.85 or newer, edition 2024.

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

Pin exact upstream commit SHAs and Cargo.lock before adding production
adapters. Do not silently switch `iroh-blobs` v0.103.1 to fork `main`.
Development plan: [STY-MASTER-PLAN-02](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd);
[canonical feature catalogue](https://app.notion.com/p/3fe32a84beec81498edde0237851cf5d).

## STY-G1b: planned resume ranges (Draft)

The [missing-range planner](src/planner.rs) lazily schedules missing byte intervals under an absolute 1 MiB per-request bound. A private-rooted VerifiedCheckpoint rejects ranges from a different immutable Manifest (root and length). Only an empty checkpoint can be created by external callers; a future Bao adapter must authenticate proof before recording any nonempty verified interval.

Nine unit tests cover gaps, duplicates/adjacency, wrong root/size, boundaries, oversized budgets and integer extremes. [ADR-0002](docs/ADR-0002-sty-g1b-range-planner.md) defines the security assumptions.

**Not yet implemented:** actual Bao range verification, Roha connectivity, durable checkpoint persistence, resumed transfer across process restarts or Akula File Gate integration. The synthetic trusted ranges used in unit tests are not evidence of cryptographic verification. No CI pass is assumed until the exact-head run completes.
