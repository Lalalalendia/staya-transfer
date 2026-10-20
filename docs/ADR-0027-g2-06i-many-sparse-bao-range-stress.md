# ADR-0027 — G2-06i bounded 64-range real FsStore stress

Lab continuation of [STY G2-06 acceptance matrix](https://github.com/Lalalalendia/staya-transfer/issues/23) after accepted G2-06g2, independent from G2-06h true ENOSPC Draft. Do not infer durable checkpoints from this experiment.

## Falsifiable checks

1. Both pinned Iroh release/fork variants import 64 **disjoint**, fully 16-KiB aligned, individually root-authenticated Bao groups into one real partial FsStore object of size `8 MiB + 17 B`, under one exclusive `StoreLease`.
2. The caller stages one bounded incoming proof at a time. Every import holds an actual `SharedAdmission` permit with a 128 KiB total in-flight byte budget, one object and four handles; after each import the RAII reservation returns to precisely zero. The running test checks Linux `/proc/self/fd` count does not grow more than 32 over the post-start baseline.
3. After actual actor shutdown, a conservative quiescent partial-file enumeration requires exactly one object, at least real data + outboard backings, <=16 file entries and <=16 MiB total **logical** lengths. This is NOT a physical allocation or adversarial quota.
4. A **different Linux OS process** obtains fresh custody, reopens actual FsStore and independently Bao-authenticates all 64 saved ranges against the immutable local full-content BLAKE3 root. Despite genuine surviving physical bytes, there must be zero published candidate checkpoints and therefore full download planning, **no unauthenticated skip**.
5. A separate purely logical 1 TiB+17 B manifest is evaluated by lazy `MissingRanges`: only first 16 bounded 1-MiB intervals may be materialized, without allocating the enormous backing. This does NOT claim 1-TiB actual FsStore disk storage.
6. Pinned release/fork normalized inventory artifacts must be byte-for-byte identical on an exact-head CI, with strict rustfmt and Clippy; do not merge on partial green.

## Scope limits

Does NOT establish a scalable durable 64-interval checkpoint-replay format, malicious concurrent writer safety, physical disk quota, crash cutpoint inside pwrite/fsync, power-loss durability, Windows retained-range skip, production supervisor or Akula File Gate. All G2-06 release HOLDs remain in place.
