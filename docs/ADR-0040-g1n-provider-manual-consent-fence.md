# STY-G1n — provider-side consent fence for a manual one-session transfer

## Goal

Close a concrete authorization gap in the existing synthetic `serve-batch` preview:
the provider previously allowed the designated QUIC receiver to GET all selected
roots as soon as it listened, even if Akula's OfferSession had not yet resolved.

## New opt-in wire test mode

- `staya-direct-preview serve-batch-gated <receiver-EndpointId> <synthetic-path...>`
  stages the exact selected 1–8 roots and prints the existing `CONNECT_BATCH`
  invitation, but the **actual provider callback rejects ClientConnected and
  every GetRequestReceived** while disarmed. GET_MANY/PUSH/observe are disabled.
- Only sender-local stdin `AUTHORIZE <Staya-queue-commitment-hex> <receiver-EndpointId>`
  can arm the exact selected manifest for up to 180 seconds from provider
  initialization. Incorrect commitment, receiver identity or expired request
  fails closed; an invitation alone never arms access.
- The provider rechecks the shared armed/expiry state on **every new GET**, not
  just at QUIC handshake. Any next sender-local line or EOF revokes access and
  closes the provider. Process exit also discards the ephemeral sender key and
  this permission.
- Legacy `serve-batch` behavior is unchanged. No user-facing Akula release
  path invokes either command yet.

## Reproducible falsifier

The real separate-process test
`provider_refuses_real_quic_before_sender_arms_and_then_stages_exact_file`
uses the **same** receiver QUIC key to attempt a real connection or GET while
the provider is disarmed; only a real error counts as a negative result (a
timeout is NOT accepted). After the sender's local authorization, that same
receiver retries, stages the selected synthetic object, independently reopens
its private on-disk output, verifies bytes/BLAKE3, and checks `NOT_APPLIED=true`.
The test runs against both pinned `iroh-blobs` release and fork dependencies.
The bin unit test also checks disarm, local revoke and expiry.

## Security interpretation and unresolved work

This is a **lab-local sender-controlled consent fence** — not an Akula device
enrollment, receiver-signed `DecisionV1`, protected host grant, durable replay
database, or production file-selection capability.

An authenticated Iroh `EndpointId` proves control of that ephemeral QUIC key,
**not** trust in an Akula `DeviceId` or a user's Vault authorization. For the
first ordinary manual file hand-off, Akula must provide a deliberately confirmed
peer-key binding, validate the receiver's exact OfferSession decision, then
invoke sender-local `AUTHORIZE`; that decision cannot come from peer-provided
labels or ticket bytes. This demo's stdin is a trusted test-controller interface,
not a stable IPC/CLI protocol for the installed app.

Source paths remain subject to initial open/reparse races despite bounded reads,
and staged output is not yet atomically published via user-selected create-new.
The provider grants repeated **bounded range GETs within one live session**, not
one network request. There is no cross-process durable revocation/ACK, no
unattended Vault sync, no installed UI integration, and no physical two-PC
acceptance. Keep the shipping network feature OFF.

## Follow-up acceptance

1. Replace local operator commands with authenticated same-user host IPC and
   exact Akula OfferSession binding; never parse network invitations as grants.
2. Use secured pinned source handles; record independent verified stage receipts.
3. Connect Akula File transfers and its selected recipient to the real sender
   process, a receiver inbox, and explicit create-new save.
4. Run installed-app Linux/Windows E2E and final two-PC tests; gate release.
