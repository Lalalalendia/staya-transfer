# STY-G2-05h3g6 — real pending FsStore startup/shutdown cancellation laboratory

Parent: supervisor #26, existing `OpeningFsStore` and `ActiveFsStore` / `ClosingFsStore` actor custody wrapper G2-05h2. Previous G2-06g2 crash phases kill the OS process **between** completed actor phases. They do not prove that dropping an actually pending load/shutdown future preserves custody.

## Exact falsifier

- A true OS subprocess polls the **actual** `ActiveFsStore::open()` (and thus pinned `FsStore::load()`) future. The test requires `Poll::Pending`, then drops that polled future. A mock guard Drop does not satisfy it. An unexpectedly synchronous `Ready` produces a FAILED/INCONCLUSIVE test instead of a false PASS.
- A second OS child opens the real pinned actor, enters closing with no outstanding permits, polls the **actual** `ClosingFsStore::finish()` (thus `FsStore::shutdown()`) future once, requires `Poll::Pending`, then drops the pending future before it could mint `QuiescentFsStore`.
- Both children must keep the real OS StoreLease contested while alive, create a diagnostic marker only after actual pending-future cancellation, and be actually killed and reaped by a separate test process. Only after process death may independent OS custody be reacquired. No clean receipt is produced.
- The shutdown branch pre-seeds a complete 16 MiB+17B file using actual pinned FsStore and clean actor shutdown. After the cancellation crash, a cold independent observer verifies physical `.data`/`.obao4` and Bao range against immutable trusted BLAKE3. Both branches require no verified checkpoint candidate.
- Pinned release and fork run on Linux and Windows in explicit CI steps, strict rustfmt + Clippy retained.

## Limits

This laboratory confirms fail-closed custody after an actual polled-future cancellation; **it does not claim deterministic interruption at a particular internal Iroh actor instruction**, nor guarantees safe actor cleanup without killing the entire process. On some upstream builds, the initial poll can complete synchronously; this is deliberately treated as inconclusive, not a fake pass. There is no power loss, production graceful CLOSE, verified resume, Akula File Gate, ALLOW/APPLIED, or signed device/vault authority. A real production supervisor still needs bounded abort/reap, worker exit witnesses, independent storage audit, and cryptographic permissions.

Do not close #26 or G2-06 based on these tests.