# ADR-0005 — STY-G1e: independently verify Bao from actual QUIC GET

Status: DRAFT; isolated CI only. Parent: [STY-MASTER-PLAN-02](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd). Follows merged STY-G1a–G1d.

## Trusted boundaries

- An immutable manifest (BLAKE3 root + declared exact size) is supplied by the **local fixture**, not by the remote peer. Production use requires a signed and authorized Akula grant, which is **not implemented** here.
- Two independent isolated harnesses use `iroh-blobs =0.103.1` from crates.io and our Git fork at `a8f5b65d3e4ae0be7d9be7907458b9f1fd56aefa`. Direct Iroh 1.3.0 QUIC and postcard 1.1.3 are pinned to match the already-resolved dependencies.
- Both providers use a genuine disposable `FsStore`. A direct-only loopback provider intercepts client admission and single-blob hash GET; GET_MANY and PUSH are disabled, Observe explicitly refused. Only one ephemeral EndpointId and one exact BLAKE3 object are allowed.
- The test manually serializes the official `Request::Get` and captures the **actual on-wire response**, bounded at `MAX_BAO_PROOF_BYTES + 8`. It checks Iroh's little-endian length header against the locally trusted manifest; it then calls the **separately authored Staya** `verify_bao_range`, requiring the exact unaligned bytes.
- A second QUIC connection transfers and verifies a second range. Mutated captured proof, appended data and altered size header must fail. An unlisted hash, unknown peer, GET_MANY and PUSH must not bypass the provider policy. Denied PUSH is judged by **lack of FsStore mutation**, never a misleading sender ACK.
- Both harness jobs export raw wire bytes; `wire-byte-for-byte` compares those bytes and manifest across release/fork. G1d's independent FsStore pre-order proof test is retained.

## Evidence needed before merge

1. Exact-HEAD `fsstore(release)`, `fsstore(fork)`, `byte-for-byte`, `wire-byte-for-byte`, Rustfmt/Clippy and root Rust contracts all SUCCESS.
2. Commit the actual Cargo-generated independent interop lockfiles, then re-run strictly `--locked` with no implicit lockfile generation.
3. Fix API conflicts/actual network read errors without weakening negative assertions or increasing resource bounds.
4. Record direct-only fixture; do not claim relay interoperability, WAN/NAT traversal, sleeping Android, durable partial resume, File Gate, vault access or a deployable sync product.

## Later gates

- Separate **relay** path test in a controlled test environment.
- STY-G2: single-writer FsStore actor, authenticated persisted Bao ranges, crash/restart, SIGKILL, inode/lock identity, quota durability and recovery.
- STY-G3: DeviceId/VaultId grants, signed manifests, staged objects and authoritative Akula File Gate with durable readback and explicit conflict handling.

Safety invariant: no write to Akula user documents, no public discovery, no direct access to production storage, no release flag.
