# STY-G1k-c — One provider, one receiver, one QUIC session for an exact selected object set

## Implemented boundary
The G1f/G1i manual direct-only `staya-direct-preview` binary now has an opt-in synthetic-only command pair:

- `serve-batch <receiver-id> <explicit-file-1> ... <explicit-file-N>`, with 1..8 local regular, non-symlink, nonzero files, <=8 MiB each and <=32 MiB combined. The local selected basenames must pass G1k queue validation. `serve` and `receive` retain their original one-file behavior.
- `receive-batch [--lab-request-unlisted]`, printing one fresh ephemeral `PEER_ID`, then accepting **one manually trusted** `CONNECT_BATCH` line containing direct endpoint ticket, order-bound selection commitment, count and exactly N triples (local label, immutable BLAKE3 root, exact length).
- One actual Iroh provider FsStore with a finite exact allowed-hash set, ONE authorized receiver `EndpointId`, `RequestMode::Intercept`, `ConnectMode::Intercept`, disabled relay, GET_MANY, PUSH, and observe. A request for any unlisted hash or outsider peer is rejected with `AbortReason::Permission`.
- One live receiver OS process, one Iroh endpoint and reused QUIC connection. Per-file bounded 64-KiB Bao GET, independent root verification, owned private FsStore staging and clean-close Bao re-audit. Per-file generated private directory+numbered stage path; peer-provided labels NEVER become output paths. Native Windows protected DACL from accepted G1j applies here too.
- Bounded G1i reconnection budget remains **session-wide**. Queue advances after full-object BLAKE3 proof of physically re-audited bytes. Outputs `STAGED_QUEUE` and `QUEUE_COMPLETE` **NOT_APPLIED=true**. No signed Akula device/vault grant, persistent identity, File Gate, or user-file publication.

## Testing required for acceptance
1. Pinned release/fork Linux and native Windows: 1 byte, 64 KiB, 1 MiB+17 synthetic selected files in a single live sender+receiver endpoint session, full physical byte equality against local selection, matching queue commitment; one alternate peer denied before staging.
2. With the **same already successful allowed connection**, `--lab-request-unlisted` sends a real GET for a hash outside the finite allowed set. Only an actual GET error (not a timeout or success) counts as negative proof. The lab flag is never a product API.
3. No user vault access or auto-discovery; every output filename generated locally. Windows negative anonymous principal real staged-file data read denied. Exact HEAD Rustfmt, Clippy, pinned release/fork byte comparison and Docker G1g regression PASS.
4. No staged output counts as durable, Akula revision ACK, or power-loss verified receipt. The acceptance result is restricted to real same-machine processes/one session.

## Outstanding caveats
- The operator must authenticate the CONNECT_BATCH line out-of-band; a digest inside the invitation by itself is not a signature. Offline sender/receiver identity continuity, expiring Device/Vault rights and revocation are NOT implemented.
- Source admission now checks the selected pathname and then consumes one opened file descriptor with a bounded `Read::take(MAX_OBJECT + 1)` rather than an unbounded `fs::read(path)`. On Unix it also rejects pre-open vs opened-handle `(dev, inode)` mismatch. This removes uncontrolled memory growth if source size changes during read, but the initial path lookup and Windows ancestor/reparse race are **not** fully secured. Lab preview remains synthetic-only; production needs safe platform-native open and handle pinning, as in [G1l #71](https://github.com/Lalalalendia/staya-transfer/pull/71).
- Windows ordinary-second-user/DACL cross-account assurance, pinned relative handles and malicious ancestor swaps remain separate [#54](https://github.com/Lalalalendia/staya-transfer/issues/54) HOLD.
- Clean shutdown does not imply a crash-safe journal or resumable checkpoint; parent/supervisor [#26](https://github.com/Lalalalendia/staya-transfer/issues/26), durable G2 [#23](https://github.com/Lalalalendia/staya-transfer/issues/23) and two physical PCs [#51](https://github.com/Lalalalendia/staya-transfer/issues/51) remain outstanding.
- This is explicitly a **small manually authorized preview**, not unattended Akula folder sync.

## Follow-up
A separately falsifiable host-bound OS custody/TOCTOU-proof file-opening layer and a signed durable policy must precede integration with Akula Sync and File Gate.
