# Feature Specification: Agent Messaging (MVP)

**Feature Branch**: `008-agent-messaging`

**Created**: 2026-05-20

**Status**: Draft (MVP)

## Why this spec exists

Siida targets human chat AND autonomous-agent messaging (see
README and feature 007). The SDK from spec 007 ships an opaque
`ChatMessage` payload (the `0x01` SDK type); a chat client treats
it as plain text. **Agents** need a richer convention: typed
messages, request/response correlation, and a "kind" discriminator
so a receiving agent knows whether a payload is a request, a
response, or an unsolicited notification.

This spec ships a **convention layer** on top of 007's
`ChatMessage`: a small wire envelope wrapped inside the chat
payload, plus an `AgentClient` thin wrapper around `SiidaClient`
that wraps/unwraps the envelope.

## User Scenarios

### US1 — Agent send/receive Request (P1)

Agent A sends a Request to agent B: `agentA.sendRequest(B, payload,
rng)`. B's `agentB.deliverAgent(envelope)` returns
`AgentIncoming.Request(senderRequestId, content)`. B then computes
a response and replies with `agentB.sendResponse(A, senderRequestId,
contentResp, rng)`. A's `deliverAgent` returns
`AgentIncoming.Response(originalRequestId, contentResp)`.

### US2 — Notification (P2)

Either party sends a one-way notification (no request id):
`agent.sendNotification(peer, content, rng)`. The receiver's
`deliverAgent` returns `AgentIncoming.Notification(content)`.

### US3 — Backward compatibility with raw chat (P2)

A peer that lacks the agent layer sends a plain
`ChatMessage(payload)`. The agent's `deliverAgent` returns
`AgentIncoming.RawChat(payload)` instead of failing — the agent
layer is a *convention*, not a requirement.

### Edge cases

- Reply to an unknown request id: surfaced to caller as
  `Response(unknown_id, content)`; the application decides whether
  to discard. The MVP doesn't track in-flight request state.
- Malformed agent envelope (claimed length ≠ actual length): the
  payload is treated as a `RawChat` so a corrupt envelope doesn't
  silently drop.

## Wire format

Inside the SDK's `ChatMessage` payload bytes:

```
offset  size  field
0       4     magic "SIAG" (0x53 0x49 0x41 0x47) — distinguishes agent envelopes from raw chat
4       1     kind: 0x01 Request, 0x02 Response, 0x03 Notification
5       16    request_id (UUID; all-zero for Notification)
21      2    content_length (uint16 BE)
23      *    content bytes (opaque to agent layer)
```

Total: `23 + content_length` bytes. Empty content allowed (0 length).

If the magic prefix doesn't match, the payload is treated as raw
chat per US3.

## Functional Requirements

- **FR-001**: `AgentEnvelope.{encode, decode}` MUST round-trip the
  wire format above bit-exactly.
- **FR-002**: `AgentClient.{sendRequest, sendResponse,
  sendNotification, deliverAgent}` MUST delegate to the underlying
  `SiidaClient` and use the SDK's `ChatMessage` (0x01) inner type.
- **FR-003**: `deliverAgent` MUST return `RawChat(payload)` on:
  - raw chat with the wrong magic prefix
  - an envelope whose length fields are inconsistent (i.e., a
    malformed envelope)
  rather than failing — the agent layer is best-effort.
- **FR-004**: Notification's `request_id` field MUST be the
  all-zero UUID (16 × 0x00); Request/Response MUST use a
  caller-supplied non-zero UUID.

## Success Criteria

- **SC-001**: Agent A → Agent B → A round-trips a request/response
  through the mixnet (via the 007 SDK) bit-exactly.
- **SC-002**: A peer that doesn't speak the agent layer (sends a
  raw 1-byte `0x42` as the chat payload) is delivered as
  `RawChat(0x42)` to the agent receiver.
- **SC-003**: A notification (kind=0x03) round-trips with
  `request_id = 16 × 0x00`.

## Out of scope

- Capability negotiation (what content types a peer accepts).
- JSON-RPC or any application-level content schema (the content
  bytes are opaque; spec 010 or higher layer defines).
- In-flight request tracking / timeouts.
- Streaming or chunked payloads.
- Identity conventions (e.g. `agent:name@host`).

## Dependencies

- 007 client-sdk (`SiidaClient` for wire transport).
- 012 HybridOnion (transitively via the SDK).
