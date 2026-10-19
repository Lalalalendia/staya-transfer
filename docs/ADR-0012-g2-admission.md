# ADR-0012 — STY-G2-05c resource admission (laboratory only)

This separate laboratory step defines bounded local reservations for number of partial objects, reserved bytes and file handles, plus retries per object. Requests use checked arithmetic; overflows, invalid inputs and capacity exhaustion are rejected without changing the ledger. Releases cannot underflow. Tests cover saturation, release/reuse and failures.

**Not implemented:** actual FsStore disk-use enforcement, memory allocation interception, globally shared reservations, on-disk recovery of reservations, cancellation fence, Windows storage durability, File Gate grants or crash-safe resumed GET. A caller must still hold an OS StoreLease, and no untrusted peer may configure limits. This is a building block, NOT a finished G2-05 or G2-06 acceptance. See [STY-G2 #7](https://github.com/Lalalalendia/staya-transfer/issues/7).
