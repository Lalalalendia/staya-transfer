# ADR-0009 - STY-G2-04a: cooperative immutable checkpoint claims

State: EXPERIMENTAL, parent [STY-G2 #7](https://github.com/Lalalalendia/staya-transfer/issues/7); [master plan](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd). This does not close G2-04 and has no Akula File Gate or user file access.

## Change

- Reuses G2-03 StoreLease OS-exclusive cooperative custody. Local-only trusted BLAKE3 root, exact object size, 16-KiB group aligned range and sequence make up a fixed 88-byte immutable checkpoint claim.
- Linux/Unix: fsync real partial data, outboard and sizes files, sync their directory, run a REQUIRED external physical audit callback, recheck file and lease identity, create_new pending record, fsync record, hardlink atomically to a never-before-used generation, sync parent dir, remove pending and sync again. A stale pending name never grants availability.
- Every read of a published record returns NeedsFreshPhysicalBaoAudit, NEVER a safe-to-skip token. The audit callback in this lab is dummy data comparison, not Bao itself. The real FsStore bridge must supply pinned bao_tree::valid_ranges verification in G2-04b.
- Windows fails closed before publication because a platform-specific directory durability barrier is not yet established. Windows tests must verify the unsupported result. Linux/Unix tests cover readback, exact identity checks, torn marker, denied audit, duplicate generation and stale pending name.
- No extra dependencies or lockfile changes: uses the existing custody crate and std filesystem APIs.

## Boundaries

Cooperative OS locks cannot stop an adversarial process writing without taking the lease. Path existence and identity checks have time-of-check/use races. The caller must quiesce the FsStore actor; this module does NOT stop it. This is not proof of post-SIGKILL or power-loss durability. Both corrupted metadata and valid metadata MUST lead to independent physical Bao audit or HOLD; none can authorize File Gate, durable APPLIED or Sync Core state.

Full G2-04 acceptance needs integration with actual pinned FsStore and a concrete independent Bao audit after fresh process reopening, plus Windows directory barrier implementation and process-level fault injection. G2-05 covers kill/restart, quotas and interruption points. Do not mark G2-04 complete based on metadata tests.