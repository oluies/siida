# Feature Specification: Async Delivery over Mixnet (MVP)

**Feature Branch**: `009-async-delivery`

**Created**: 2026-05-20

**Status**: Draft (MVP — in-memory + file-backed)

## Why this spec exists

A round of the mixnet (spec 004) produces a `Vector[MailboxEnvelope]`
addressed to per-recipient mailbox ids. If a recipient is online and
polling, they pick up their envelopes immediately. If they are
**offline**, those envelopes need to be held somewhere — a
**dead-drop / mailroom** — until they reconnect.

The README sketches "NATS JetStream as a dead-drop OR dtn7-rs." Both
are out-of-scope for the MVP (network infra). This spec ships the
**`Mailroom` abstraction** and two in-process implementations:

1. `Mailroom.inMemory(ttl)` — a HashMap with expiry.
2. `Mailroom.persistent(path, ttl)` — file-backed snapshot.

A future spec wires `Mailroom.nats(…)` or `Mailroom.dtn(…)` to a
real bundle store; this MVP defines the contract.

## User Scenarios

### US1 — Deposit + retrieve (P1)

After a round, the mixnet's Coordinator delivers
`MailboxEnvelope`s. The deployer's adapter loop calls
`mailroom.deposit(env, now)` for each. Later, a recipient queries
`mailroom.retrieve(mailboxId, now)` and gets the pending envelopes
back in deposit order, then the mailroom drops them.

### US2 — TTL expiry (P1)

Envelopes have a TTL configured at mailroom construction. Once
`now > deposit_time + ttl`, the envelope is dropped silently at the
next access (lazy expiry — no background sweeper in the MVP).

### US3 — Persistent restart (P2)

`Mailroom.persistent(path, ttl)` stores envelopes on disk. After
a restart, retrieve returns the same envelopes (minus any that
expired during the downtime).

### Edge cases

- Cover-traffic mailbox (`MixChain.CoverMailboxId = 0L`) is dropped
  on deposit — it carries random bytes, not real traffic.
- Broadcast mailbox (`-1L`) is also dropped (no broadcast in the MVP).
- Concurrent depositors/retrievers on the same `Mailroom` are NOT
  supported (single-threaded discipline). A future spec can layer
  Pekko-actor mediation.

## Functional Requirements

- **FR-001**: `Mailroom.deposit(env, now)` MUST return `Boolean`
  indicating whether the envelope was stored (false for cover /
  broadcast / expired-immediately).
- **FR-002**: `Mailroom.retrieve(mailboxId, now)` MUST return the
  pending envelopes in **insertion order** and clear them from the
  mailroom in the same call.
- **FR-003**: Expired envelopes MUST NOT be returned and MUST be
  dropped from the mailroom on next access.
- **FR-004**: The persistent store MUST atomically rewrite the
  state file on each deposit/retrieve (same write-tmp + rename
  pattern as spec 020's `FriendStore.persistent`).
- **FR-005**: The persistent store's wire format MUST start with
  `0x53494D52` (`"SIMR"` magic), version byte `0x01`, then a run
  of records each: `8B deposit_time_ms | 2B BE mailbox_count | 2B BE env_len | env bytes` (one record per envelope).

## Success Criteria

- **SC-001**: Deposit 3 envelopes (different mailboxes), retrieve
  one mailbox, get exactly the deposit-order envelopes for that
  mailbox; the other two remain.
- **SC-002**: An envelope deposited at t=0 with TTL=60s is dropped
  by a retrieve at t=120s (the call returns empty and the count is
  zero afterwards).
- **SC-003**: Persistent mailroom: deposit 2 envelopes, close, open
  a new mailroom at the same path, retrieve recovers them with
  insertion order preserved.

## Out of scope

- NATS JetStream / dtn7-rs binding (future spec).
- Background expiry sweeper.
- Concurrency / multi-writer.
- Receipts / acknowledgements.
- Encryption-at-rest of the persistent store.

## Dependencies

- 004 mixnet-server (`MixChain.MailboxEnvelope`).
