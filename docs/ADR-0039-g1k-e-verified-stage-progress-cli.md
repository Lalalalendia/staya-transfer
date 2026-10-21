# STY-G1k-e — Honest progress in the manual multi-object QUIC preview

## Accepted prerequisites
- G1k-a/b/c are merged into main, including real one-session direct Iroh QUIC with manually approved finite object-set access.
- G1k-d [PR #69](https://github.com/Lalalalendia/staya-transfer/pull/69) added `QueueCursor::verified_staging_progress` as the only authoritative *whole-object BLAKE3 staging* counter. Network packets, unverified Bao ranges, retries and remote completion messages are not the progress authority.

## Implementation
After a received object is independently Bao/cold-audited, physically written to generated protected staging and then **reopened and BLAKE3-verified from the final written staging file**, the receiver advances QueueCursor. Only then does the existing `STAGED_QUEUE` output carry:

- `VERIFIED_ITEMS=done/selected`
- `VERIFIED_BYTES=done/selected`
- `PHASE=Running|Complete`

The existing `ROOT`, `SIZE`, `RECONNECTS`, `NOT_APPLIED=true` and generated staging filename remain unchanged. `QUEUE_COMPLETE` includes the same fields and refuses to report success if verified item/byte counts are not exact. No added progress lines alter the one-session caller's output parsing.

## Real E2E test
The pinned Iroh release/fork plus native Windows sender/receiver separate-process test sends three synthetic files in one manually authorized QUIC connection, denies outsider and unlisted hash, independently cold reads all staged bytes, and checks per-item progress against independently calculated totals. First and second items must stay Running and below 100%; third and completion must be Complete with exact full BLAKE3-verified counts. No extra receipt is minted from network bytes.

## Explicit HOLD
This is **staged-content progress**, not a network transfer percentage, durable checkpoint, final destination write, Akula revision ACK or user sync success. Source initial path races, signed Device/Vault policy, crash-safe retained resume and two physical PCs remain independent gates. The output is human-readable diagnostic preview CLI, not a stable machine API or GUI.
