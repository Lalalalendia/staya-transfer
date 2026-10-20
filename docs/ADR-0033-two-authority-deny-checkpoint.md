# ADR-0033: fail-closed two-authority DENY checkpoint coordination (research)

**Status:** Draft / standalone Go laboratory; stacked on STY Draft #57 (mTLS owner writer), #53 (signed DENY event), #50 (YDB conditional CAS), #47, #45, #42 and #40. Product stays `HOLD`. No installed Akula/Staya runtime changes.

## Problem and explicitly bounded threat model

One well-formed, strongly consistent YDB row and a correct owner signature are insufficient to detect a privileged DB administrator restoring a previously valid snapshot. The signed event becomes replayable after the database is restored. The writer service's mTLS and application validation do not constrain an administrator holding the broad database editor/restore privilege.

This lab introduces **a second, separately controlled monotone CAS authority** (a *fence*) bound to the same installation, vault, global epoch and complete DENY-floor digest. The fence must be administered with its **own credentials, distinct recovery and backup authority, distinct writer principals, and independent anti-rollback protections**. The Go constructor can reject an identical pointer and bind one tenant. **It does not and cannot prove these organizational/hardware properties.** A second Go object, VM or key on the same CI host is not an independent trust root.

## The two-authority contract

`TwoAuthorityDenialAnchor` implements the existing `TrustedDenialAnchor` port, so the pinned Ed25519 `SignedDenyCASGate` and the HTTPS/mTLS `OwnerDenyGateway` can use it without any positive permission API:

- `Read`: fresh **fence read first**, fresh YDB primary read second. Require exact equality of namespace, epoch, digest and domain-separated commitment; malformed/missing/offline/divergent inputs return `ErrAnchorHold`. No cache or fallback.
- `CompareAndSeal`: require canonical `old`/`new` checkpoints and **epoch +1**. First require `Read == old`; then CAS **fence first**, CAS **primary second**, and finally require a fresh `Read == new`. Every uncertain outcome returns `HOLD`. No retry, auto-repair, promotion from one successful backend, or access grant.
- At the application boundary the separate `SignedDenyCASGate` remains mandatory for verifying **full before/after DENY maps**, one replica increment and the pinned policy-owner signature. `TwoAuthorityDenialAnchor` is a consistency primitive, not itself a policy authorizer.

## Why the ordering matters and what it cannot guarantee

The independent fence advances first. After the YDB row is restored by a privileged YDB-only administrator, the fence remains at a newer checkpoint and every read/old-signature replay returns `HOLD`. This holds **only if the attacker cannot also change or rewind the fence**.

Two remote CAS operations **are not an atomic distributed transaction**. If fence seal succeeds and primary seal fails, the fence becomes ahead. All reads, retries, and new signed operations must HOLD until an **explicit external, independently reviewed recovery**. If the first CAS was committed but the response was lost, the second CAS must not run. If primary CAS commits but its acknowledgement is lost, the invocation still returns HOLD even if a later diagnostic read finds both advanced. In particular, a later diagnostic equality is **not** a grant and cannot silently complete the prior operation.

No automatic reconciliation, rebase, epoch reset, re-sign, or 'pick maximum epoch' is allowed. An attacker who controls and can restore **both** authorities can still replay a valid old signed transition; this is a tested counterexample and a release blocker.

## Evidence and falsifiers

Go 1.23 lab tests use the actual HTTPS Document API mock for the primary, a separate in-memory simulated fence, the existing signed transition gate, and a real TLS 1.3/mTLS gateway fixture. Tests cover:

1. Signed DENY `0→1` passes exactly once; malicious restoration of the YDB row is rejected before another `UpdateItem`, including through real mTLS.
2. Fence unavailable or refusing its CAS => zero primary writes; wrong tenant/invalid canonical checkpoint => HOLD.
3. Fence advances but primary fails => persistent divergence and no implicit retry.
4. Fence commit with lost response => primary untouched; primary commit with lost response => invocation HOLD, even if both later read as equal.
5. Two concurrent signed transitions => exactly one success, one HOLD and exactly one primary CAS.
6. **Dual rollback falsifier:** restoring *both* prior states accepts a replay; the test intentionally exposes, rather than solves, this problem.

Windows and Linux CI must be green at the exact HEAD before research acceptance. All changed files are limited to `interop/owner-witness-lab`, ADR-0033 and inherited research-only workflow guards. No credentials, live YDB database, physical second machine, IAM admin separation or durable nonrollbackable fence were provided or deployed.

## P0 before any production right

1. **Real custody**: two separately administered, actually deployed authority services, with independent principals/backups; client/desktop never receives writer token. Prove no shared administrator or ability to restore both roots with one credential.
2. **Durable monotonic fence**: concrete hardware/external immutable audit or equivalent nonrollbackable service with a defined recovery process. Test privileged restore, machine reboot, power loss and partitions on actual infrastructure.
3. **Recovery protocol** for a fence-ahead/primary-behind state reviewed by the policy owner. Do not implement silent retry or fabricated equality.
4. **Complete policy root** including positive grants, identity/channel binding and File Gate's independent authorization. The current checkpoints only cover DENY floors.
5. Actual two-host controlled field test and a reviewed integration with Akula after production trust gates. Not now.

**Release invariant:** `Read == checkpoint`, `Seal == nil`, HTTP 204, `ConsistentDenialSnapshotOnly` and 'both CAS complete' are *diagnostic DENY-state consistency only*, never `ALLOW`, APPLIED, ACK, File Gate write or user-file modification. Product remains `HOLD`; `main` and installed Akula are unchanged.
