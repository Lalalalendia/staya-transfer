# ADR-0026 — STY-G2-06h kernel ENOSPC inside pinned FsStore

Isolated lab for [G2-06 issue #23](https://github.com/Lalalalendia/staya-transfer/issues/23). Earlier G2-05g tests relied on logical sidecar quotas and `/dev/full` audit callbacks; neither is accepted as a real actor ENOSPC proof.

1. Linux CI mounts a private size=32 MiB tmpfs. The real pinned release/fork FsStore successfully stages a locally BLAKE3-root-authenticated first Bao range, creating actual partial `.data` storage.
2. A filler on that same real filesystem allocates pages until Linux returns ENOSPC (errno 28). With actor still open, a different, nonoverlapping Bao range **must fail** inside real FsStore write I/O; no checkpoint can be created by the failed import.
3. `strace -ff -yy` is mandatory. CI explicitly searches for errno `ENOSPC` on `write`/`pwrite` on actual FsStore `.data`, `.obao4`, or `.sizes4` FDs; filler-only ENOSPC never qualifies. Raw process syscall traces are retained as GitHub artifacts; normalized release/fork fail-closed evidence must match byte-for-byte.
4. The filler is removed, actor stopped and an independent OS process reopens actual FsStore. There must be zero checkpoint candidates and `VerifiedCheckpoint::empty` must schedule a full redownload.

Fail closed when mount capability, strace, a real FsStore physical sidecar write error, recovery or pinned-version evidence cannot be demonstrated. CI-only experiment; no changes to Akula or installed product.

Limits: Linux tmpfs exhaustion is real kernel resource exhaustion but not a persistent disk power-loss simulation. No mid-syscall kill, production disk quota, Windows directory durability, hostile path swap, File Gate or G2-06 release authorization.
