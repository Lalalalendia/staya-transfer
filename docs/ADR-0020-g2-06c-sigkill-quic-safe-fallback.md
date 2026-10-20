# ADR-0020 — STY-G2-06c Linux process death and actual QUIC second transfer

**Scope:** experimental Linux pinned release/fork network + subprocess bridge, stacked on [G2-06b PR #28](https://github.com/Lalalalendia/staya-transfer/pull/28), linked to [G2-06 acceptance #23](https://github.com/Lalalalendia/staya-transfer/issues/23). No production authority, no Akula File Gate.

Two independent real Linux receiver-process modes are tested with the same locally trusted immutable BLAKE3 root, exact size and Bao profile:

- `uncommitted`: real first QUIC GET of an aligned interior range, worker imports verified Bao into a pinned real FsStore under StoreLease and is SIGKILLed **without** shutdown or checkpoint. Even if bytes appear on disk, candidate count MUST be zero; a subsequent QUIC connection GETs **all** bytes into a brand-new private receiver FsStore root. Recovered uncommitted data is never skipped.
- `checkpointed`: first actual GET/import, actor clean shutdown, physical file+outboard sync and independent Bao audit under OS custody, then append-only candidate generation. Worker is forcibly killed after the checkpoint barrier. A new OS process obtains the lock, reads candidate only as untrusted, independently validates actual physical Bao against the trusted root, checks a newly verified first-wire proof agrees byte-for-byte, and requests **only** missing aligned ranges on a second QUIC connection. Reassembled data is compared byte-for-byte and via full BLAKE3.
- Both modes capture exact first/post-kill GET bytes and range inventory, and CI compares fork vs release artifacts; no dependency/lockfile changes.
- The first actual network proof is passed to worker via a **private test-only local file**; this is not a deployed network receiving process. Parent keeps first wire in test RAM to check returned bytes; a production restart could not trust it without a new authenticated proof. The cold journal has no MAC and remains a candidate until physical validation.

**Strict exclusions:** this is SIGKILL/process-exit evidence, not power-loss durability, crash at every barrier, multihost/WAN/relay, hostile races or adversarial path custody, Windows directory durability, Akula grants/Vault/File Gate, any durable APPLIED acknowledgment, or full G2-06 release. Worker subprocess is a disposable test harness, not the accepted G2-05h3a supervisor. Linux OS lock #17 remains a separate dependency, as do G2-05h2/#24 and h3a/#27. If the standalone test fails, keep G2-06 and this PR on HOLD.

**Acceptance for this narrow PR:** exact-head Linux pinned release and fork --locked, two actual post-kill QUIC scenarios, at least three raw GET proofs per mode, full trusted BLAKE3, byte-for-byte cross-variant evidence and no false retained-range skip. No green status until CI proves it.

## Writer-custody review refinement

The pre-kill competing `StoreLease::acquire` assertion checks specifically for `io::ErrorKind::WouldBlock`, not any unrelated filesystem failure. On the `uncommitted` safe full-retry path, the destination is a **new** physical FsStore root, so an independent `StoreLease` is acquired and retained until its actor shuts down. Holding custody for the killed root alone does not authorize writing to the fallback root. The test explicitly confirms another cooperative writer gets `WouldBlock` for that fresh root. This closes a test-only ownership gap; it does not prove adversarial path safety or a production G2-06 session supervisor.
