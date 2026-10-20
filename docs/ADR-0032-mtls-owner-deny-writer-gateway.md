# ADR-0032: mTLS owner DENY writer gateway (research-only)

**Status:** Draft / isolated lab. Stacked after STY Draft #53, #50, #47, #45, #42 and #40. No deployed cloud service, installed Akula change, real YDB identity, File Gate, positive grant, APPLIED or ACK.

## Problem and boundary

A validated owner-signed transition is not a least-privilege credential. The YDB Document API writer identity can call other APIs outside our Go wrapper or restore an older row. An Akula desktop must never own the YDB token or select a table/operation. This ADR introduces one narrow TLS service boundary, **not** an antirollback guarantee.

`OwnerDenyGateway` is created **inside a separately operated writer process**, holding a `SignedDenyCASGate` already bound to the pinned policy-owner Ed25519 public key and a `TrustedDenialAnchor` (YDB adapter in the HTTPS mock tests). The process alone may obtain a YDB IAM token from an owner-only source. `OwnerDenyGatewayClient` has no IAM provider, YDB database path, or `TrustedDenialAnchor` capability.

### Wire contract

- TLS **1.3** with server-side `RequireAndVerifyClientCert` plus independently pinned client certificate SPKI SHA-256. The gateway is also pinned to one nonzero `(Installation, Vault)` namespace; even a validly signed proposal for another vault is refused before the YDB read. The client verifies certificate chains, server hostname and separately pinned gateway TLS SPKI; it refuses redirects and ambient proxy forwarding.
- Only `POST /v1/deny/seal` with exact `application/json`, no query, no `Authorization` bearer, no generic Document API proxy endpoint. Maximum request body **2 MiB**, at most four active worker requests, strict JSON with unknown fields and trailing data rejected.
- Body: `{ "transition": SignedDenyTransition, "signature": base64(Ed25519-signature) }`. The signature authenticates the canonical **entire** before/after DENY floor maps via their checkpoint commitments, epoch and target replica. See ADR-0031 for the exact signed byte format and invariants.
- Server returns **204 No Content** only after a fresh trusted backend read, one conditional CAS, and another trusted read confirming the new DENY checkpoint. Any malformed, unauthenticated, stale, illegal, cancelled, offline or ambiguous operation is an HTTP denial translated into `ErrAnchorHold` by the client. A 204 is **never** authorization to read/write files.
- The gateway exposes no positive permission API, no arbitrary YDB `GetItem`, `PutItem`, `UpdateItem`/table selection, no caller-supplied policy-owner key and no token-issuing endpoint. No implicit retries or cached previous success.

### Validation evidence

The Go standard-library lab includes two real HTTPS servers with separate responsibilities: an mTLS owner gateway and a YDB Document API `httptest` fixture reachable only via the gateway's `TrustedDenialAnchor`. Tests prove that a signed one-step DENY transition reaches a single conditional CAS and a replay fails; malformed bodies, unknown paths, additional JSON, credential-bearing client requests, excessive bodies, bad TLS pins, missing client certificate, correctly signed foreign namespaces or forged owner signature never reach the remote backend. A separate **OS process** is launched with disposable TLS identities and an in-memory CAS fixture, establishing a real mTLS client/server boundary and rejecting repeated requests after the first CAS. Both OS processes share one test runner; test identities do not represent separate operators.

CI must pass on actual Linux and Windows runners (Go 1.23), including `go test`, `go vet`, Linux race detector and OS-process tests. Scope controls accept only named research files; no source under `src/`, `custody/`, `interop/fork/` or Akula changes.

### Deliberate unsolved attack and release gate

- The separately **deployed** owner writer, private IAM identity, credential rotation, process sandbox, tenant binding to a specific YDB and protection of signer configuration have **not** been implemented. The gateway is an HTTP handler and a test child process, not a service installer or production deployment.
- A privileged YDB editor or backup-restorer can overwrite the signed CAS result with an older *valid* row and then replay a previously valid signed DENY transition. Existing ADR-0031 negative test demonstrates this counterexample. Neither mTLS nor CAS nor two matching witnesses can defeat simultaneous rollback of their independent roots.
- Real antirollback requires an independently administered durable monotonic authority or externally immutable attested log, with a resolved conflict/recovery protocol and a concrete threat model for DB admin and backup restore. Live YDB end-to-end IAM permission tests and two **physical** hosts remain unexecuted.
- The checkpoint currently covers only **DENY floors**. Positive grants, per-peer QUIC identity, File Gate write entitlement, cancellation/recovery and released-binary provenance remain out of scope.

**Mandatory result:** Product `HOLD`. Never interpret a successful `Seal`, HTTP 204 or `CONSISTENT_DENIAL_ONLY` as a P2P grant, APPLIED, ACK or File Gate write.
