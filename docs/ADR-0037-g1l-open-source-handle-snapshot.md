# STY-G1l-a — Pinned source-handle snapshot, no second path lookup

## Invariant
The Transfer core can consume one **already opened** `std::fs::File` and a locally selected immutable manifest; it must not open a pathname again during extraction. `snapshot_pinned_open_file(File, SelectedFile)` consumes the descriptor and checks:
- selected label/root/nonzero size via the existing G1k queue constraints;
- the handle represents a regular file, with the exact expected size;
- bounded seek/read of at most declared bytes + 1, no unbounded filesystem read;
- exact size and file type **rechecked on that same handle after read**;
- the complete BLAKE3 root matches the independently pinned selected manifest.

It returns an owned bounded byte snapshot that can later be seeded into a private FsStore. There are no native unsafe bindings, network access, file publication, symlink metadata trust, or new Akula authority in this library function.

## Test matrix
- Positive 64 KiB+17 descriptor: exact label, bytes, selected root.
- Same-length content replacement: BLAKE3 rejection.
- Shorter or longer content: size rejection, no success.
- Unsafe local label, empty or >8 MiB pinned selection: rejection before reading.
- Unix renamed/replaced source pathname **after opening the descriptor** still reads only the original pinned file (real OS inode behavior).

## Security boundary and remaining work
This API starts **after** the descriptor has been opened. It does NOT make `File::open(path)` safe against symlinks, junctions, ancestor swaps, device redirects, or malicious initial picker paths. The future Akula/native launcher must obtain handles with a platform-specific secure-open policy (Linux openat2/dirfd no-follow constraints and explicit Windows reparse-point/handle identity controls); then pass handles to Transfer rather than paths. Linux/Windows adversarial open races are still untested. This step only removes the **second pathname lookup** inside Transfer.

Do not silently replace the G1k-c lab `serve-batch <paths...>` with a purported production-safe API; that command remains a disposable synthetic-file preview. Add separately falsifiable OS opener tests before sensitive source documents are enabled.

No signed Device/Vault grants, Windows ordinary-user DACL, G2 crash-safe resume, independent physical two-PC test [#51](https://github.com/Lalalalendia/staya-transfer/issues/51), or Akula File Gate are claimed. See [#55](https://github.com/Lalalalendia/staya-transfer/issues/55).
