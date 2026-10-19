# ADR-0006 — STY-G2-01: fail-closed durable transfer recovery contract

**State:** design and policy scaffold only (NOT durable persistence). **Parent:** [STY-G2 issue #7](https://github.com/Lalalalendia/staya-transfer/issues/7), [master plan](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd). **Precondition:** G1e real loopback QUIC gate merged. This change does not touch Akula, S3, user files, storage or relays.

## Ownership and identity

- The trusted Akula authority (future G3) must issue an immutable `(BLAKE3 root, exact byte size, Bao profile)`; transport IDs and ACKs are insufficient.
- The G2 writer will use the *existing pinned* `iroh-blobs` FsStore, behind a narrow storage adapter. Do not implement a duplicate Bao/object database. Storage and checkpoint paths must be private to Staya, never selected by peers.
- Exactly one *process* may own a store. An in-memory mutex, stale filename, or a lockfile-exists check is not sufficient. Acquire and hold an OS-enforced exclusive lock for the whole session; test process, symbolic-link, hard-link and path aliasing separately on Linux and Windows. A restarted process must re-establish ownership rather than trusting prior ownership metadata.
- Neither a successfully received packet nor a correctly verified Bao range can grant access to Akula Vault, publish a file, or create a durable APPLIED receipt. G3 alone will call File Gate.

## Ordering of a durable checkpoint (design; NOT implemented)

1. Authenticate the locally trusted manifest and peer grant in the future Akula bridge. Reject unknown profile, size, identity or unauthorised peer before network GET.
2. Verify incoming Bao against trusted root and exact length. Apply bounded request, staged byte, outboard, disk, object and process limits.
3. Under exclusive writer ownership, hand the verified bytes to pinned FsStore; track real, stable file and store identity. Do not infer durability from an in-memory bitmap.
4. Flush data and Bao/outboard metadata to stable storage. Write checkpoint into a separate temporary file, flush it, rename it atomically on the same volume, then perform the platform-supported directory/metadata durability barrier. Do not acknowledge durable checkpoint before these barriers and a successful readback policy.
5. After restart, reacquire sole ownership, compare the exact root, size and profile, and independently revalidate the actual stored bytes and their Bao authentication tree. Only a separately implemented, physical-audited result may feed the missing-range scheduler. A published journal marker alone never authorizes a skipped byte.

**Unresolved implementation details for G2-02:** enumerate pinned FsStore APIs for partial range persistence, outboard flush and reopen; evaluate FsStore shutdown against SIGKILL; define separate checkpoint index ownership and whether the existing backend exposes required durable barriers. Until verified, a lost cache causes a safe full retry instead of claiming resume.

## Restart policy implemented in this PR

`src/recovery.rs` supplies pure `decide_reopen(expected, observed)` and explicit states. On a matching published checkpoint it returns **AuditPhysicalDataAndBao**, never Resume. Wrong root, length or profile, incomplete or corrupt metadata, missing data/outboard and concurrent owner return **Hold**. A genuinely new exclusive empty private store returns initialization only. The classifications are not observations of the filesystem, and the caller must not equate them with an OS lock or a passed Bao proof.

## Planned failure injection, required before any durable claim

- Kill after proof verification, after staging data, after outboard write, after data/outboard barrier, after checkpoint temporary-file barrier, after rename and after directory barrier; verify fail-closed recovery.
- Spawn two unrelated writer processes and test lock lifetime, same path reached through aliases, move/replace races, and startup recovery. Test Linux `SIGKILL` and Windows `TerminateProcess` independently.
- Corrupt/truncate data, outboard and checkpoint. Wrong root/length must HOLD. Retained bytes may be skipped only after independent readback+Bao evidence on actual persistent volume.
- Enforce whole-store and per-object resource caps and test actual disk-full and cancellation. Existing G1 memory bounds are NOT physical disk quotas.
- Verify exact SHA and `Cargo.lock --locked` on Linux and Windows. Do not promote G2 to green based only on unit tests in this PR.

## Gates and exclusions

**Done by G2-01:** public fail-closed restart classification, root+size+profile identity, explicit negative unit tests, this ADR. **Not done:** FsStore adapter, OS file locks, fsync/rename, crash-durable checkpoint, quota enforcement, SIGKILL/Windows tests, NAT/relay, Roha/noq fork-path validation, Akula File Gate or user sync. Continue [G2-02 through G2-06](https://github.com/Lalalalendia/staya-transfer/issues/7) in order.