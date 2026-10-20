# STY-G2-06e - checkpoint checksum forgery and journal replay

Narrow cross-platform custody tests against the existing checkpoint reader; they do not create a production resume capability.

The first test changes the root in a real journal record and recomputes its unkeyed BLAKE3 metadata checksum. The locally trusted immutable root must still reject it.

The second test copies a checksum-correct journal into a different private store. Parsing still returns an *untrusted candidate*; it never supplies Bao proof or permits skipping bytes. The foreign object's root and size fail the local identity fence.

These tests do not access Akula user files or prove physical data/outboard survival, hostile path custody, Windows directory durability, real QUIC resume, or the full seven-row G2-06 acceptance matrix.