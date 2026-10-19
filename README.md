# Staya Transfer

Transport-independent, resumable and bounded transfer of content-addressed byte objects for the Staya network. Initial phase: a small Rust library with explicit transfer contracts and tests; not a deployed sync service.

## Boundaries

- `noq` provides QUIC packet/stream semantics, and `roha` provides secure peer connections, discovery, NAT traversal and relay paths.
- This repository schedules immutable blob ranges, verifies returned bytes through an explicit verifier/adapter, manages resumable transfer checkpoints, source selection and budgets. `iroh-blobs` is a candidate implementation of the Bao/BLAKE3 transfer and streaming adapter; it is not silently vendored here.
- `WOW` handles protected short events, envelope delivery and signed receipts independently.
- Akula owns user/device ACL, revision DAG, sync, File Gate and durability acknowledgements. **Receiving bytes never authorizes modifying a user document.**

## Status

Bootstrap only. No working peer-to-peer file transfer or production integration yet. See the [Staya master plan](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd) and the [feature catalogue](https://app.notion.com/p/3fe32a84beec81498edde0237851cf5d).

## Development

A dedicated Rust crate and CI are the first milestone. Releases must pin and test Roha, noq and the selected blob backend by immutable commit SHA; do not trust floating upstream dependencies or treat a network ACK as a durable Akula commit.
