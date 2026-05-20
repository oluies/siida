# Feature Specification: Chat Client (MVP — session model)

**Feature Branch**: `010-chat-client`

**Created**: 2026-05-20

**Status**: Draft (MVP — headless session model)

## Why this spec exists

Vuvuzela had a terminal `gocui` UI. Siida targets multi-platform
Scala UIs (terminal + desktop GUI); both will share a headless
**session model**. This spec ships that model:

- `ChatSession` aggregates a `SiidaClient` (007), a `FriendStore`
  (019/020), and an in-memory message log.
- Operations: send chat to a friend by **alias** (UTF-8 string), poll
  delivered envelopes for inbox lines, list friends, look up by
  alias.

UIs (terminal, desktop, mobile, web) layer on top of `ChatSession`
in follow-up specs.

## User Scenarios

### US1 — Compose + send by friend alias (P1)

A user types `:msg bob hi`. The session looks up "bob" in the
FriendStore, resolves to (identity, public bundle), and calls
`siidaClient.sendChatMessage(...)`. The session records the
outgoing line in its history.

### US2 — Inbox poll (P1)

After a mixnet round, the calling layer hands inbound
`MailboxEnvelope`s to the session via `session.deliverInbound(envBytes)`.
The session decrypts via the underlying SDK, appends the chat to
history, and returns the new `ChatLine`. If the SDK returns an
`AddRequest` instead, the session surfaces it as a pending
add-request the UI can prompt about.

### US3 — Friend listing (P2)

`session.friends()` returns the list of known aliases (the
FriendStore's insertion-order identities). `session.lookup(alias)`
returns the `(identity, bundle)` if present.

### Edge cases

- Compose to unknown alias → `Left(SessionError.UnknownFriend)`.
- Inbound delivery to wrong mailbox → `Left(SessionError.NotAddressedToMe)`.
- Inbound message from an unknown sender → still appended to
  history as `ChatLine.Inbound(senderUnknown, payload)` — the UI
  decides whether to prompt for an add-request.

## Functional Requirements

- **FR-001**: `ChatSession.create(siida, friendStore)` MUST return
  a session referencing those collaborators without copying state.
- **FR-002**: `session.sendChat(alias, text)` MUST UTF-8-encode the
  text and call the underlying `SiidaClient.sendChatMessage`. The
  result on success is the outgoing `OnionLayer`.
- **FR-003**: `session.deliverInbound(envelopeBytes)` MUST accept
  the cleartext envelope bytes from the mixnet (post-peel) and
  surface a typed `InboundEvent`.
- **FR-004**: `session.history()` MUST return chat lines in the
  order they were recorded (sent or received).
- **FR-005**: Friend lookups MUST use the `FriendStore` exclusively
  (no implicit PKG-directory consult in the MVP — that's the
  session's caller's job to populate the FriendStore beforehand).

## Success Criteria

- **SC-001**: alice and bob, each with a `ChatSession`, exchange a
  chat round-trip: alice's session composes "hi bob", the mixnet
  delivers, bob's session surfaces it as `ChatLine.Inbound("alice",
  "hi bob")`.
- **SC-002**: `session.history()` returns lines in chronological
  order: outbound A → inbound A → outbound B → inbound B.

## Out of scope

- Terminal UI (TUI) — a follow-up spec.
- Desktop GUI / mobile UI — follow-up.
- Persistent chat history — follow-up.
- Notification of unread messages — follow-up.
- Mailbox routing alias (per-recipient nicknames) beyond what the
  FriendStore exposes.

## Dependencies

- 007 client-sdk (`SiidaClient`).
- 019/020 friend-store (`FriendStore`).
