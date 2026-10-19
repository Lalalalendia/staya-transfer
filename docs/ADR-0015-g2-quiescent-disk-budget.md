# ADR-0015 — STY-G2-05g: quiescent FsStore logical disk budget and ENOSPC refusal

Parent: [G2 issue #7](https://github.com/Lalalalendia/staya-transfer/issues/7). [Master plan](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd).

This lab adds `custody::disk_budget` to enumerate the *quiescent* pinned `iroh-blobs` partial `data` directory under a held cooperative StoreLease. Only four supported sidecar formats are admitted (64-hex-root `.data`, `.obao4`, `.sizes4`, `.bitfield`). Reject unknown filenames, symlinks/reparse points, nonregular entries, unexpected data directory, excessive distinct objects, too many entries, integer overflows and excessive cumulative `metadata.len()`. Hard upper scan bounds are 512 entries, 128 roots and 64 GiB of **logical file lengths**. All violations fail closed, without deleting user/actor data or publishing checkpoint records.

A separate release/fork interop test imports real authenticated Bao into the exact pinned FsStore, cleanly shuts it down, samples the actual sidecar lengths, proves a too-small limit refuses, independently verifies persisted Bao, and confirms that a disk-snapshot result does not mint a checkpoint. No new storage engine.

On Linux, `custody/tests/disk_budget.rs` uses an **actual write to /dev/full** to generate OS `ENOSPC` within the G2-04b physical-audit callback. The pending checkpoint must not be published on failure. This is a real kernel ENOSPC code path, but it does **NOT** force the upstream FsStore actor's own writes to run out of physical disk. Windows has no matching /dev/full fixture and still cannot claim a durable directory barrier.

**Explicit boundaries:** logical lengths count sparse holes and are neither allocated physical space nor filesystem free capacity. This snapshot only runs *after* quiescence; it cannot enforce storage growth during an active FsStore import, protect against adversarial filename swaps, or cap redb or other files outside the known partial data directory. This is not a hard disk quota and does not solve real FsStore ENOSPC injection, cancellation of upstream writes, Windows directory durability, resumed GET, G2-05/G2-06 release, Akula File Gate or Vault authority.

Accept only with exact-head cross-platform custody Rustfmt/Test/Clippy and release/fork pinned interop Cargo.lock tests. G2-05f in-flight reservation (PR #19) and G2-05d Linux lock diagnosis (PR #17) are independent; avoid backporting one stage onto the other prematurely.
