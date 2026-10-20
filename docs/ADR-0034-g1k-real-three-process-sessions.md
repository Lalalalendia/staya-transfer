# STY-G1k-b — three real sequential one-object Iroh sessions (integration proof)

## What is actually implemented

A Rust integration gate composes the **existing accepted G1f/G1i `staya-direct-preview`** into the G1k-a immutable ordered queue. Three local synthetic files of sizes 1 byte, 64 KiB and 1 MiB+17 are selected and locally bound to their immutable BLAKE3 roots and sizes. For **each** item the test spawns fresh real sender/receiver OS processes, manually pins the ephemeral permitted receiver, moves exactly one object over actual direct Iroh QUIC, verifies Bao and cold physical staged bytes, independently reads the staged file, and asks the G1k queue to advance only on the exact selected manifest and bytes.

An unrelated receiver uses the SAME ticket on items 1 and 3 and must fail without STAGED. Windows and Linux use pinned release and fork Iroh variants, and separate CI comparison jobs demand identical byte-for-byte physical results for all 3 objects. Output artifacts include only deterministic public synthetic bytes and locally computed roots/sizes, no tickets, peer identifiers, paths or keys.

## What this does **not** implement

- This is **three explicitly authorized independent single-file sessions**, *not yet* one continuously authorized multi-object session, a user-facing queue CLI, a discovered peer, a multi-object protocol, persistent queue storage or a batch File Gate.
- Cancel, pause and retry are verified in the pure queue core, NOT live OS-process cancellation or suspended/resumed network transfers.
- Every session uses a new ephemeral sender and receiver. One-time per-file permission must not be extrapolated to a signed multi-file Device/Vault grant.
- A STAGED stdout line is NOT trusted alone: the receiver and then test independently read physical bytes and compare to the locally selected BLAKE3 root. No durable checkpoint, OS owner auth, Windows power-loss guarantee, APPLIED or Akula write permission.
- On the current base, Windows TEMP ACL is **not production confidentiality**. [G1j #58](https://github.com/Lalalalendia/staya-transfer/pull/58) is a separate mandatory private staging prerequisite. Physical two-PC field acceptance [#51](https://github.com/Lalalalendia/staya-transfer/issues/51) remains OPEN.

## Next independently verifiable slice

Implement a **single** bounded manifest/ticket + single provider session serving an exact locally authorized object set with per-hash GET admission; consumer receives each object into generated numbered files; refused outsider and unlisted hash; native private staging and interruption tests. Do not silently broaden the existing public one-object preview to new peer rights.
