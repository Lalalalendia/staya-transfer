# ADR-0001 — STY-G1: bounded transfer contract (laboratory only)

Status: experimental; not a production downloader, sync service, or Akula File Gate.
Parent roadmap: [STY-MASTER-PLAN-02](https://app.notion.com/p/3fe32a84beec81e5acf7c081fe5e0bfd).

## Ownership

- Akula remains the sole owner of DeviceId, VaultId, ACL, revision DAG,
  conflict resolution, durable File Gate publication and user-visible ACK.
- Roha provides authenticated sessions, discovery, direct and relay paths.
- noq is QUIC, never an application acknowledgement.
- iroh-blobs supplies Bao verification, content-addressed store and resume.
- Staya Transfer provides explicit scheduling, bounded resource contracts and
  adapter interfaces. It MUST NOT create a second Sync Core or write into
  Akula's vault by itself. WOW is separate short-message infrastructure.

## What is actually implemented

The `lab::fetch_complete` mock reads bounded byte ranges from in-memory
`RangeSource` implementations. It caps each request at 1 MiB, each test
object at 8 MiB, sources at 16 and retries at 8, regardless of external
request configuration. It does not make sockets or filesystem writes.

Returned `VerifiedObject` has private constructors and is minted only
after comparing **the complete byte stream** to the BLAKE3 root in an
immutable `Manifest`. Corrupt bytes, mismatched response lengths,
unauthorized access, exhausted attempts, oversized manifests and
cancellation fail closed. Partial bytes are dropped, not promoted.

`VerifiedRanges` is only an interval ledger; its caller MUST supply a
prior Bao-verified range. It is not itself a cryptographic primitive.
Do not treat mocked sources as authenticated peers. No transient
network error is automatically retried after an auth or integrity error.

## What this deliberately does NOT claim

- No Bao range authentication; a whole-object BLAKE3 is sufficient only
  after *all* bytes were fetched.
- No Iroh/Roha/noq transport, NAT, real multi-device test or network ACL.
- No persistent, crash-safe resume checkpoint, streaming write, S3
  compatibility, signed grants or pin/seed implementation.
- No File Gate promotion, protected writes or production release.
- No proof against an attacker mutating an on-disk FsStore inode.
  P2P-BLOB-11a laboratory evidence is distinct from 11b writer exclusion.

## Next gates

1. STY-G1b: A/B pinned `iroh-blobs` tag v0.103.1 vs fork main exact
   commit, pin compatible Roha/noq and Cargo.lock; compare regressions.
2. STY-G1c: integrate an authentic Bao-verifying range backend, with
   negative proof fixtures, bounded IO, and durable resume.
3. STY-G2: enforce cooperative single-writer FsStore lifecycle using
   upstream store actor/RPC where feasible; test competing processes,
   SIGKILL, fork-inherited locks and restart.
4. STY-G3: request-to-manifest grants, hash-verified immutable staging,
   then Akula File Gate and durable readback; feature flag initially OFF.

Evidence rules: commit SHA + relevant CI runs + source version + explicit
`Code / CI / E2E / Released` states. No new duplicate functional backlog.
