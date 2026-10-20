# STY / RN-4E1b-03c1b2: online owner epoch witness (protocol lab)

This is a **standalone Go standard-library test lab** in `staya-transfer`.
It is not imported by Akula, Staya Transfer Rust, its installer, or File Gate.
No peer grants, positive policy, APPLIED, ACK or user-file writes exist here.

It proves an independently running OS process can answer a fresh challenge
through **TLS 1.3 mutual certificate authentication** and a pinned server
public key. It signs a strictly canonical head message with Ed25519 containing
installation ID, vault ID, global epoch, SHA-256 digest of the **entire sorted
DENY-floor map**, and 32 random challenge bytes. The client verifies both TLS
and the owner signature and refuses old local epochs, unsealed local advances,
same-epoch state divergence, wrong owner identity, invalid signature, replayed
nonce, owner outage, and missing or corrupt owner head.

Test: `go test -count=1 ./...` (Go 1.23+, no third-party modules).
Includes a **real separate OS-process** TLS server and a cold-reopen test.
The helper's disposable CA, keys and environment variables are test-only.

## Security boundary / remaining blockers

- The server's head file is assumed **already** installed in an *independent*
  trusted owner domain. The lab only reads it. SHA-256 of that file is merely
  damage detection: replacing the owner's own head with an old valid copy is
  NOT defeated. Real owner write ownership, monotonic storage, physical file
  identity, signed provisioning, fsync/power-loss, backup/restore and key
  rotation are **not implemented**.
- An online owner must be available for each decision. No offline grace,
  cached authorization or previous-success fallback exists; a timeout = HOLD.
- Cryptographic freshness means a response was signed for this nonce, not
  proof that the owner operator or its persistent storage could not rollback.
- TLS certificates and signature keys are temporary fixtures, not product
  credentials; these tests run on loopback, not on separate physical hosts.
- The supported digest covers *denial floors only*. A future complete policy
  must be cryptographically bound to the policy head before any grant is safe.
- No bridge to the existing Windows test-only revocation journal is provided;
  no actual owner-operated service has been provisioned or tested.

**Release gate:** Do NOT authorize P2P or write files from this lab's only
successful verdict, `CONSISTENT_DENIAL_ONLY`. Next integrate a deployed trusted
owner (separate host), durable monotonic CAS on the owner, fixed installer
identity, physical two-host network tests, real QUIC origin proof, and File Gate
write/recovery. TPM may be an optional offline provider, not a substitute for
binding the counter to a complete signed policy digest.
