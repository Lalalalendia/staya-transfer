# STY-G1k-d — Verified staging progress, not network ACKs

## Purpose
The G1k-a queue in `main` provides an immutable ordered file list, complete-root BLAKE3 receipts and fail-closed HOLD/cancel. Downstream clients need a progress snapshot, but using QUIC bytes, an unverified range, or remote "done" as completed transfer is incorrect.

## New API
`QueueCursor::verified_staging_progress() -> VerifiedStagingProgress` returns:
- `selected_items`, `selected_bytes` (from the already bounded and immutable local manifest),
- `verified_staged_items`, `verified_staged_bytes` (derived *only* from items with `ItemOutcome::VerifiedStaged`),
- terminal or nonterminal `QueuePhase`, plus `remaining_items()` and `remaining_bytes()`.

No independent counter or externally reported bytes can alter these values. Error, cancellation, pause and retry must not advance them. Unit tests check initial, paused, once-verified, corrupt-held, cancelled and complete cases.

## Deliberate limits
This value means only that an exact complete byte buffer was verified against an immutable selected BLAKE3 root in the queue. The queue itself cannot attest to a file system, OS owner, fsync/power-loss durability, remote authorization, File Gate, APPLIED or Akula revision ACK.

## Next integration
After the single-session lab preview [G1k-c #67](https://github.com/Lalalalendia/staya-transfer/pull/67) is accepted, wire this snapshot to its receiver as explicit `VERIFIED_STAGE_PROGRESS` records **after** actual private-file physical readback and local `record_verified_staging`. Keep speculative transfer-activity separate if needed. Never display a single ambiguous "100% synced".

The follow-up negative test must tamper with one selected file after a successful first receipt and assert that only the first file counts while the phase becomes HOLD. See [Issue #55](https://github.com/Lalalalendia/staya-transfer/issues/55). Physical two-PC gate [#51](https://github.com/Lalalalendia/staya-transfer/issues/51) remains separate.
