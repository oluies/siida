# Feature Specification: Client SDK (MVP)

**Feature Branch**: `007-client-sdk`

**Created**: 2026-05-20

**Status**: Draft (MVP — local composition)

## Why this spec exists

By 2026-05-20 every cryptographic + transport primitive Siida needs
is in `main`: HybridOnion (012), PqSignature (013), MultiSignedEntry
(014), IdentityEncryption (015), Friendship add-request (019),
MailboxEnvelope + layered submission (004), PKG + directory entries
(005), ConfigChain (006). Each is wired to its peers via opaque
types and typed errors, but nothing yet *composes* them into the
end-user-facing flow:

> "alice wants to send a chat message to bob, who is in the PKG
> directory at identity `bob@siida`."

This spec ships that composition as a single `SiidaClient` trait. It
runs **locally only** — no network transport. The follow-up specs
(008 agent-messaging, 009 async delivery) layer transport on top of
the wire bytes this SDK produces.

## User Scenarios

### US1 — alice sends a chat message to bob (P1)

Alice has a `SiidaClient` configured with: her secret bundle, the
PKG directory, the mix chain's public bundles. She calls
`client.sendChatMessage("bob@siida", payload, rng)`. The result is
an `OnionLayer` ready to feed into the mixnet round.

**Acceptance**:
1. Lookup of "bob@siida" against the directory succeeds.
2. The directory entry's MultiSignedEntry proof validates against
   the configured roster + threshold (= the chain's current view).
3. The chat payload is wrapped in an SDK inner envelope (1-byte type
   `0x01` + payload bytes), end-to-end encrypted via
   `HybridOnion.encrypt(bob.publicBundle, …)`, placed inside a
   `MailboxEnvelope(bob.mailboxId, e2e_layer)`, and finally
   layer-encrypted through the mix chain via
   `MixChain.layeredSubmission`.

### US2 — bob delivers an envelope routed to his mailbox (P1)

Bob's mailbox at the last mixer holds a cleartext `MailboxEnvelope`
with his mailbox id. He calls `client.deliver(envelope_bytes)`. The
SDK strips the e2e onion, peels the SDK type byte, and surfaces an
`IncomingMessage` ADT:

- `IncomingMessage.ChatMessage(payload)`
- `IncomingMessage.AddRequest(content)` (US3 below)

### US3 — alice sends bob an add-request (P1)

Alice calls `client.sendAddRequest("bob@siida", rng)`. Internally:
`Friendship.buildAddRequest` produces the AddRequest ciphertext;
the SDK wraps it as SDK type `0x02` and routes it through the
mailbox/mix-chain path identical to US1. Bob's `deliver` returns
`IncomingMessage.AddRequest`, holding the verified
`AddRequestContent` (sender identity + sender public bundle).

### US4 — Cover traffic (P2)

Alice's client emits a cover-traffic submission for any round in
which she has no real message:
`client.coverSubmission(payloadLen, rng)`. Under the threat model
(constitution v2.0.0 Principle I), every participant's round
submission is on-the-wire indistinguishable from every other's.

### Edge cases

- Identity not in directory → `IdentityNotInDirectory`.
- Directory entry's MultiSignedEntry fails verification → `BadDirectoryProof`.
- Delivered envelope mailbox-id mismatch → `WrongMailbox`.
- Delivered envelope SDK type byte is unknown → `UnsupportedSdkType`.
- Delivered envelope inner decrypt fails → `DecryptionFailed`.

## Functional Requirements

- **FR-001**: `SiidaClient` MUST be a pure-function trait —
  every operation is `(input, rng) → Either[SdkError, output]` or
  similar. No internal mutable state for the MVP.
- **FR-002**: SDK envelope wire format (sits inside
  `MailboxEnvelope.payload`):
  ```
  offset  size  field
  0       1     SDK type byte (0x01 chat, 0x02 add-request)
  1       *     inner content (opaque to SDK; type-specific)
  ```
- **FR-003**: The chat-message inner is the user's payload bytes
  end-to-end encrypted to the recipient's HybridPublicBundle via
  `HybridOnion.encrypt`; on the wire it is the serialised OnionLayer.
- **FR-004**: The add-request inner is a `Friendship.AddRequest`
  serialised via `Friendship.serialiseAddRequest`.
- **FR-005**: Directory lookups MUST run through the configured
  `Directory` (from spec 015) and validate the per-identity
  MultiSignedEntry proof against the configured `ConfigChain`'s
  current view (roster + threshold + DST).
- **FR-006**: `deliver` MUST reject envelopes whose mailbox id
  does not match the client's own mailbox id.
- **FR-007**: `coverSubmission` MUST delegate to
  `MixChain.coverSubmission` so cover and real traffic are
  on-wire indistinguishable.

## Success Criteria

- **SC-001**: alice → bob chat round-trips: alice sends, mixnet
  peels (using the `004` Coordinator), bob delivers, payload bytes
  recover bit-exactly.
- **SC-002**: alice → bob add-request round-trips: bob's `deliver`
  returns the verified `IncomingMessage.AddRequest` with sender
  identity matching alice's bytes and sender bundle matching her
  directory binding.
- **SC-003**: A tampered envelope (last-byte flip) is rejected with
  `DecryptionFailed`.
- **SC-004**: A directory entry with a stale roster (signed by an
  old roster after rotation) is rejected with `BadDirectoryProof`.
- **SC-005**: Cover traffic produces the same byte-length OnionLayer
  for the same payload length as a real submission.

## Out of scope (deferred)

- Network transport / Pekko remoting / NATS.
- Persistent client state (history, retries, dedup).
- Cats Effect 3 fiber/effect wrapping (this MVP is plain Scala).
- Multi-recipient broadcast.
- Friendship-key dial tokens (future 019 follow-up).
- Add-response handling (auto-add) — surfaced to caller; caller decides.

## Dependencies

- 012 HybridOnion, 013 PqSignature, 014 MultiSignedEntry, 015
  IdentityEncryption (directory shape), 004 MixChain, 005
  Pkg/IssuedIdentity/DirectoryEntryWire, 006 ConfigChain, 019
  Friendship.
