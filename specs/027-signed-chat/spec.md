# Feature Specification: Signed Chat Messages

**Feature Branch**: `027-signed-chat`

**Created**: 2026-05-21

**Status**: Draft (MVP)

## Why this spec exists

Spec 023 introduced the `0x03 AuthenticatedChat` SDK envelope — the
sender's identity is now on the wire, and the recipient can resolve
it against the FriendStore to render `<- alice: ...`. Spec 023's
own text calls out the gap:

> "The session does NOT verify that the claimed sender identity
> actually owns the corresponding HybridPublicBundle (no signature;
> chat messages aren't signed). The trust step happens during
> friend-discovery."

That's a real attack. Identity bytes are public. Anyone who can
encrypt to bob's `HybridPublicBundle` (which is everyone) can send
a payload `(sender_id = alice_id, "hi I'm alice")`. Bob's FriendStore
reverse-lookup binds `alice_id → "alice"` and renders the spoof as
genuine. The HybridOnion ciphertext is integrity-protected but
unauthenticated wrt the sender.

This spec adds the **signed chat** path: a new SDK envelope type
`0x04` whose inner payload carries an ML-DSA-65 signature over
`(0x04 || sender_id || recipient_id || chat_payload)`. The
recipient verifies against a signing-key bound to the sender in
the FriendStore. Spoofs are detected and dropped.

## User Scenarios

### US1 — Alice sends a signed chat to bob (P1)

`alice.sendSignedChatMessage(bobIdentity, "hi bob", rng)` builds
the inner payload `(sender_id, sig, chat)` where
`sig = PqSignature.sign(alice_sigSk, 0x04 || alice_id || bob_id || chat)`,
e2e-encrypts to bob's bundle, and ships through the mixnet. Bob's
`deliver` returns
`IncomingMessage.SignedChat(aliceIdentity, "hi bob".bytes, sig)`.

### US2 — ChatSession verifies signatures (P1)

Bob's `ChatSession.deliverInbound(envBytes)` decodes the signed
chat, looks up alice's signing public key in the FriendStore,
recomputes the signed bytes (binding to bob's own identity as the
recipient), and runs `PqSignature.verify`. On success it returns
`InboundEvent.Chat(ChatLine.Inbound("alice", "hi bob"))`.

On signature failure (forged sender or tampered payload), the
delivery returns `SessionError.SignatureFailed`. On missing-key
(no signing key registered for that sender in the FriendStore),
the delivery returns `InboundEvent.Chat(ChatLine.Inbound("?[unverified]", text))`
— the application can prompt for an add-request to rotate to a
signed binding.

### US3 — Cross-recipient replay is rejected (P1)

A signed chat from alice→bob, if intercepted and replayed by an
attacker as alice→charlie (assuming charlie also has alice as a
friend), MUST fail verification on charlie's side, because the
signed bytes bind `recipient_id` and charlie's identity ≠ bob's
identity.

### US4 — Backward compat with 0x03 AuthenticatedChat (P2)

Existing `sendAuthenticatedChatMessage` (0x03) and the matching
`IncomingMessage.AuthenticatedChat` continue to work unchanged.
`ChatSession.sendChat` picks the signed path automatically when
the SiidaClient was constructed with a signing key; otherwise it
falls back to the authenticated path.

### Edge cases

- SiidaClient constructed without a signing key: `sendSignedChatMessage`
  returns `SdkError.SigningKeyMissing`.
- Inner payload's declared `sig_len` doesn't match the wire-format
  size for ML-DSA-65 (3310 bytes): `SdkError.MalformedEnvelope`.
- Persistent FriendStore does NOT store signing keys in this MVP
  (the on-disk wire format is unchanged). In-memory FriendStore
  does. A future spec extends the persistent format with a
  version bump.

## Wire format (SDK inner payload, after type byte 0x04)

```
offset  size       field
0       2          sender_identity_length (uint16 BE)
2       N          sender_identity_bytes
2+N     2          signature_length (uint16 BE; must equal 3310)
4+N     3310       signature_bytes (ML-DSA-65 over signed-message)
3314+N  *          chat_payload_bytes
```

Signed message (input to `PqSignature.sign` / `verify`):

```
0x04 || u16(sender_id_len) || sender_id || u16(recipient_id_len) || recipient_id || chat_payload
```

The recipient identity is NOT on the wire — the verifier supplies it
from its own `siida.identity`. Binding the recipient stops
cross-recipient replay.

## Functional Requirements

- **FR-001**: `SdkEnvelope.Type.SignedChat: Byte = 0x04` MUST be added.
- **FR-002**: `SiidaClient.sendSignedChatMessage(recipient, payload, rng)`
  MUST sign over `0x04 || sender_id || recipient_id || payload` and
  emit a `0x04`-typed envelope per the wire format above.
- **FR-003**: `SiidaClient.IncomingMessage.SignedChat(senderIdentity,
  payload, signature)` MUST be added; `deliver` MUST return it
  for incoming `0x04` envelopes (verification is NOT done at the
  SDK layer; the FriendStore is in the ChatSession layer).
- **FR-004**: `ChatSession.deliverInbound` MUST verify the signature
  using the sender's signing key from the FriendStore. On verification
  failure it MUST return `SessionError.SignatureFailed` and MUST NOT
  append to history.
- **FR-005**: When the FriendStore has no signing key for the sender,
  `ChatSession.deliverInbound` MUST surface the chat as
  `ChatLine.Inbound("?[unverified]", text)` so the UI can warn the
  user.
- **FR-006**: `ChatSession.sendChat` MUST automatically use the
  signed path when the underlying SiidaClient has a signing key;
  otherwise it MUST use the authenticated path (spec 023).
- **FR-007**: `FriendStore` (in-memory) MUST gain `addWithSigningKey(
  identity, bundle, sigPk)` and `lookupSigningKey(identity)` methods.
  The existing `add(identity, bundle)` and `lookup(identity)` MUST
  remain unchanged.
- **FR-008**: `AgentClient.deliverAgent` MUST handle the new
  `SignedChat` variant (treated the same as `AuthenticatedChat` —
  decode the agent envelope; sender field is not surfaced at the
  agent layer in this MVP).

## Success Criteria

- **SC-001**: A signed chat alice→bob with a matching signing key
  in bob's FriendStore verifies, surfaces as `Inbound("alice", text)`,
  and is appended to history.
- **SC-002**: A signed chat where the inner payload's `sender_id`
  bytes are swapped to a different identity (without re-signing)
  fails verification and returns `SessionError.SignatureFailed`.
- **SC-003**: Replaying a signed chat (alice→bob) into charlie's
  session fails verification (recipient binding).
- **SC-004**: A signed chat from an identity whose signing key
  is not in the FriendStore surfaces as `Inbound("?[unverified]", text)`.
- **SC-005**: `ChatSession.sendChat` against a session whose
  SiidaClient was constructed without a signing key emits a 0x03
  AuthenticatedChat (backward-compatible path).

## Out of scope

- Persistent FriendStore signing-key storage (deferred; on-disk
  format bump required).
- Signed add-requests (spec 019 / 020 friend-discovery has its
  own trust hinge via the directory).
- Per-message replay protection beyond the recipient binding
  (a nonce/timestamp scheme is a follow-up).
- Signed cover-traffic.

## Dependencies

- 013 PqSignature (ML-DSA-65 sign/verify).
- 023 AuthenticatedChat (this spec is the cryptographic upgrade
  of 023's identity-on-the-wire path).
- 019 Friendship (signing key is bound at friend-add time — but
  this MVP just exposes the API on FriendStore; binding via
  add-request is a follow-up).
