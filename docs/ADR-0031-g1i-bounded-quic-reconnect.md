# STY-G1i — Bounded same-ticket direct QUIC reconnect (laboratory preview)

## Scope
Extend the already accepted manually authorized one-file `staya-direct-preview` (G1f) and Docker network experiment (G1g), not Akula Sync or a new transfer backend. The receiver may recover from a failed **individual QUIC GET** while the sender's original session remains active. The original pinned endpoint ticket, receiver's ephemeral identity, immutable BLAKE3 root, exact size and Bao profile must not change.

## Runtime contract
- Max **two reconnects per entire 8 MiB-or-less transfer**; no unbounded retries or silent relay fallback.
- When a GET fails or times out, retry the **same range**, never increment the cursor before independent Bao verification and bounded FsStore staging. If reconnect fails or budget is exhausted, error and never emit `STAGED`.
- A malformed size prefix, Bao verification failure, storage admission refusal or changed root **never** becomes a retryable verified range; fail closed. A timeout or transport error can cause a new QUIC connection to the original endpoint only.
- Reuse the same receiver endpoint and ephemeral key for this one operator-approved session. No persisted identity, no automatic discovery or new permission. The provider's event policy re-evaluates the original allowed receiver on every connection.
- Expose `RECONNECTS=N` in `STAGED` solely as diagnostic evidence; `NOT_APPLIED=true` remains obligatory.
- `receive --lab-drop-after-first-range` is explicitly non-production fault injection. It closes a real QUIC connection after a verified first range. The second GET must genuinely fail and reconnect without discarding already authenticated ranges. A size of one or fewer range(s) refuses the lab flag.

## Independent acceptance
1. The original one-file/manual ticket authorized/outsider-denied two-process test remains green on Linux and Windows, pinned release and fork.
2. Separate OS-process test intentionally closes **real QUIC**, then receives the same root with `RECONNECTS=1`, cold physical Bao audit, byte-perfect independent readback and an unrelated peer denied.
3. Strict rustfmt + Clippy and both pinned dependency variants PASS at the exact PR HEAD. Docker G1g remains green; no changes to network topology, raw tickets or credential logging.
4. Both negative/positive tests use synthetic public bytes only and preserve `NOT_APPLIED=true`. No Akula user file mutation.

## Explicit HOLD
This improves **in-session** resilience only, not crash-safe process restart or durable multi-range checkpoint replay (G2-06); peer authorization is an ephemeral manually trusted invitation, not signed Device/Vault grants. Windows inherited TEMP DACL, hostile local path swaps, independent two-host LAN/NAT, production supervisor #26 and File Gate remain unproven. The lab flag must not be represented as a production API. Do not claim general network recovery when the provider exits or the authorized receiver key is lost.
