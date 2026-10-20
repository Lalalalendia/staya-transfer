# ADR-0026: owner-online monotonic witness protocol experiment

**Status:** research, draft; NO production authority. Tied to Akula Draft
[#467](https://github.com/Lalalalendia/Akula/pull/467), [#464](https://github.com/Lalalalendia/Akula/pull/464)
and protected Windows provenance [#460](https://github.com/Lalalalendia/Akula/pull/460).
Tracked by STY-MASTER-PLAN-02 in Notion.

## Decision

Explore an online **independent owner authority** first because Akula targets
Windows, Linux, phone, server, and router environments. Requiring a TPM NV
counter everywhere prevents these deployments. A Windows TPM/NV witness is a
separate possible *offline* optimization only after real hardware provisioning,
authorization, wear limits, power-cut and migration behavior are proven.

Never conflate a protected signing key (CNG/TPM) with protected policy history:
signing an old snapshot is possible if the signing service's state rolls back.
The independent owner must durably preserve one monotonically advancing
(installation, vault, epoch, complete-policy-digest) head. On its failure or
conflicting epochs, the local client **refuses**, never self-heals by adopting
whichever file appears newer. An online signed challenge blocks simple network
replay, not a compromise/rollback of the owner itself.

## This PR's evidence, not release acceptance

A separate Go module exercises TLS 1.3 client authentication and pinned
server identity, an Ed25519-signed challenge-bound head, canonical complete
DENY-floor digest, and real distinct OS-process owner restart. Local older
or newer head, same-sequence different digest, missing owner, wrong TLS pin,
wrong signer key, replayed response, invalid file all result in HOLD. The
only success is `CONSISTENT_DENIAL_ONLY` and cannot leave this lab.

## Hard gates after this lab

1. Deploy an owner on a **separate physical host**, with signed installed
   identity and OS-protected key plus immutable namespace ancestry.
2. Establish durable owner-side CAS and an **independent non-rollback anchor**
   (or explicitly trust the owner's durable anti-rollback storage). Test killed
   writers, power loss, all head/sidecar files, old valid owner snapshots.
3. Bind the entire grant+revoke policy, issuer identity, vault, physical local
   replica root, owner signing-key rotation, and freshness/availability policy.
4. Integrate the Rust Akula Broker with an authenticated transport; no data
   supplied by an untrusted IPC client can assert authenticated QUIC identity.
5. Verify with two real computers, malicious peers, offline/reconnect,
   ownership transfer/migration, and File Gate no-replace recovery.

Until then, all production positive grants and user-file writes remain HOLD.
