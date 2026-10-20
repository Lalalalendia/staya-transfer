# ADR-0031: pinned-owner signed DENY transition gate (research only)

**Status:** Draft / laboratory only. Stacked on STY Draft #50 (YDB Document API CAS), #47, #45, #42, #40. No Akula product integration. Neither File Gate, grants, QUIC permissions, APPLIED nor ACK is enabled.

## Security problem

The YDB `ConditionExpression` of RN-4E1b-03c1b6 compares the previous epoch and checkpoint bytes before storing a requested new digest. This defeats concurrent stale writes, but **does not prove the next digest represents a legitimate revoke**. A caller supplying an arbitrary valid SHA-256 commitment can advance the row unless the remote writer independently verifies the operation.

Yandex Cloud currently has a `ydb.viewer` role (read-only) and a broad `ydb.editor` role (which also permits schema and backup operations). There is no supported user-defined role permitting *only* the application's conditional UpdateItem. Consequently, the credential-bearing writer must run under a **separately administered service**, must never send its IAM token to Akula, and must apply its own policy check before any DB request. Even then, a privileged DB operator or compromised gateway token can bypass application restrictions.

Official role documentation: https://yandex.cloud/en/docs/ydb/security/

## Protocol: AKULA_DENY_TRANSITION_V1

The client proposes a `SignedDenyTransition` with:

- Exact previous and next `DenialCheckpoint` (installation, vault, global epoch, DENY digest, domain-separated commitment).
- Full before and after `Floor` maps, each with at most 4096 unique, nonzero replica IDs and positive counter values.
- Exactly one nonzero target replica ID, with its floor incremented **by exactly 1**. No other floor may change or disappear and no unrelated floor may be added.
- Global epoch increasing by exactly 1; global epoch must equal the sum of the individual floor counters before and after (the existing DENY-only journal invariant).
- An Ed25519 signature by the **preconfigured/pinned policy owner public key** over the canonical domain, previous and next commitments, replica ID, and previous/next global epochs.

The verifier recomputes both SHA-256 map digests and checkpoint commitments from the supplied full maps. An unauthorized addition, deletion, decrement, arbitrary new digest, duplicate device, wrong vault or global epoch rollover is `HOLD`. An invalid signature or unknown owner key is `HOLD` **before any remote HTTP call**.

`SignedDenyCASGate.Seal` then performs a fresh `TrustedDenialAnchor.Read`, exact previous checkpoint comparison, a single conditional `CompareAndSeal`, and a fresh read of the resulting checkpoint. No automatic retry or grant exists. Lost acknowledgement, stale CAS, network errors and divergence return `HOLD`. The transition gate itself never directly edits the owner's local journal.

## Test evidence and falsifiers

- Real loopback TLS YDB Document API emulator: valid owner-signed `0 -> 1` DENY event advances exactly once. Replaying the exact signature against the newer database epoch returns `HOLD` without another UpdateItem.
- Forged owner key, tampered checkpoint or signed-but-illegal before/after floors are rejected before any GetItem/UpdateItem.
- Two concurrent owner-signed requests on the same epoch yield precisely one CAS winner and one `HOLD`.
- **Intentionally failing antirollback claim:** privileged remote DB restore can replace the latest row with an earlier valid row. The same old owner signature can then be replayed successfully. This negative counterexample is an expected test PASS and remains a mandatory production HOLD.

All experiments run in the isolated Go 1.23 owner-witness lab. CI checks Linux/Windows, Go tests, `go vet`, Linux race detector and strict own-file scope.

## Required before production

1. Independently provisioned owner service with authenticated request identities and pinned policy-owner public key; explicit lifecycle for signing-key rotation and revocation.
2. A protected full-policy store of **positive and negative grants** with complete canonical digest. The current proof only applies to DENY floor increments and **cannot grant file access**.
3. Trust anchor independent of YDB writer/admin and its backups, tested against physically restoring both journal and DB row to an earlier valid state; immutable externally controlled audit or hardware-backed monotonic state.
4. Real cloud YDB (not HTTPS mock), separately owned IAM principal, exact authenticated deployment, service restart/power-cut/partition tests and two physical hosts. No `ydb.editor` IAM token in clients, GitHub secrets or application logs.
5. Explicit File Gate review after grants and QUIC identity binding are implemented. A successful `Seal` **must never be used as ALLOW**.

This ADR does not claim a live writer gateway is implemented, nor that two signers on the same machine constitute independent custody. Main and installed Akula stay unchanged. Product stays HOLD.
