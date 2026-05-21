# Feature Specification: Authenticated Chat + Sender-Alias Resolution

**Feature Branch**: `023-authenticated-chat`

**Created**: 2026-05-21

**Status**: Draft (MVP)

## Why this spec exists

Spec 007's SDK `ChatMessage` (type byte `0x01`) carries an opaque
payload — the recipient knows the payload but not who sent it. The
spec-010 `ChatSession.deliverInbound` surfaces inbound chats with
the placeholder alias `"?"` because the sender's identity isn't on
the wire.

This spec adds the **authenticated chat** path: a new SDK envelope
type `0x03` whose inner payload prefixes the sender's identity
bytes before the chat content. Receivers can decode the identity,
reverse-look-up the alias in their `FriendStore`, and surface
inbound chats as `Inbound(alias, text)` for real.

Privacy-wise: revealing the sender to the recipient is the WHOLE
POINT of chat. The metadata-privacy goal is that the mixnet /
network adversary can't link sender to recipient. The recipient
knowing who is talking to them is a feature, not a leak. (Cover
traffic and the agent layer still get the plain `ChatMessage`
path when anonymity inside the recipient's view matters.)

## User Scenarios

### US1 — Alice sends an authenticated chat to bob (P1)

`alice.sendAuthenticatedChatMessage(bobIdentity, "hi bob", rng)`
wraps the payload as `(2B alice_id_len, alice_id_bytes,
"hi bob".bytes)`, end-to-end encrypts that to bob's bundle, and
ships through the mixnet. Bob's `deliver` returns
`IncomingMessage.AuthenticatedChat(aliceIdentity, "hi bob".bytes)`.

### US2 — ChatSession surfaces the alias (P1)

Bob's `ChatSession.deliverInbound(envBytes)` decodes the
authenticated chat, looks up `aliceIdentity` in bob's `FriendStore`,
and returns `InboundEvent.Chat(ChatLine.Inbound("alice", "hi bob"))`.

If the sender's identity isn't in bob's FriendStore, bob's session
returns `ChatLine.Inbound("?", "hi bob")` (same fallback as
unauthenticated). The application UI can prompt for an add-request
in that case (using the surfaced sender identity bytes).

### US3 — Backward compat with plain ChatMessage (P2)

The existing `SiidaClient.sendChatMessage` (type `0x01`) and
`IncomingMessage.ChatMessage(payload)` continue to work
unchanged. `ChatSession`'s deliver path handles BOTH variants —
authenticated chats surface with a resolved alias, plain chats
surface as `Inbound("?", text)` per the existing spec-010 contract.

### Edge cases

- An authenticated chat from a sender whose identity bytes are
  empty (length 0) is rejected with `SdkError.MalformedEnvelope`.
- An authenticated chat whose declared sender-id length exceeds
  the inner payload's remaining bytes is rejected with
  `SdkError.MalformedEnvelope`.
- The session does NOT verify that the claimed sender identity
  actually owns the corresponding HybridPublicBundle (no
  signature; chat messages aren't signed). The trust step happens
  during friend-discovery (spec 019 `verifyAddRequest`); after
  add-request acceptance, the FriendStore binding is treated as
  trusted.

## Wire format (SDK inner payload, after type byte 0x03)

```
offset  size  field
0       2     sender_identity_length (uint16 BE)
2       N     sender_identity_bytes
2+N     *     chat_payload_bytes (opaque to this layer)
```

Total: `2 + N + payload_len` bytes inside the e2e ciphertext.

## Functional Requirements

- **FR-001**: `SdkEnvelope.Type.AuthenticatedChat: Byte = 0x03` MUST be added.
- **FR-002**: `SiidaClient.sendAuthenticatedChatMessage(recipient,
  payload, rng)` MUST send the SDK envelope with type byte `0x03`,
  inner payload formatted per the wire spec above, e2e-encrypted
  to the recipient's bundle.
- **FR-003**: `SiidaClient.IncomingMessage.AuthenticatedChat(
  senderIdentity, payload)` variant MUST be added; `deliver` MUST
  return it for incoming `0x03` envelopes.
- **FR-004**: `ChatSession.deliverInbound` MUST resolve the sender
  alias via `friendStore.list()` reverse-lookup. Unknown senders
  yield `"?"`.
- **FR-005**: `ChatSession.sendChat(alias, text, rng)` MUST switch
  to the authenticated path (so two sessions can hold a real
  conversation with each other's aliases visible).
- **FR-006**: Existing `sendChatMessage` (type `0x01`) MUST remain
  available; existing tests MUST stay green.

## Success Criteria

- **SC-001**: alice → bob authenticated chat round-trips through
  the mixnet; bob's session reports `Inbound("alice", "hi bob")`.
- **SC-002**: Unknown sender (not in bob's FriendStore) surfaces
  as `Inbound("?", text)` with the raw sender bytes still
  accessible via the IncomingMessage variant.
- **SC-003**: A plain `0x01` chat still surfaces with `"?"` alias
  (no regression in spec-010 backward compat).
- **SC-004**: A tampered authenticated envelope (last-byte flip)
  yields `SdkError.DecryptionFailed`.

## Out of scope

- Signed chat messages (the authenticator here is bundle-based
  decryption + FriendStore trust, NOT a per-message signature).
- Group chat.
- Per-message read receipts.

## Dependencies

- 007 client-sdk (`SiidaClient`, `SdkEnvelope`).
- 010 chat-client (`ChatSession`).
- 019/020 friend-store (`FriendStore`).
