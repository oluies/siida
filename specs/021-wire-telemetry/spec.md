# Feature Specification: Wire Telemetry into Coordinator / Mailroom / PKG

**Feature Branch**: `021-wire-telemetry`

**Created**: 2026-05-21

**Status**: Draft (MVP)

## Why this spec exists

Spec 018 shipped the `Telemetry` abstraction (counters, gauges,
histograms) but nothing in the codebase calls it. This spec wires
the abstraction into the three components an operator most cares
about:

- **Coordinator** (mixnet round metrics): how many submissions
  came in, how many deliveries went out, per-mixer drop counts.
- **Mailroom** (async-delivery backlog): deposits, retrieves, and
  the current per-mailbox count after each operation.
- **Pkg** (identity issuance): how many identities have been
  minted and how many `IdentityAlreadyExists` rejections.

Each component gains an *optional* `Telemetry` constructor
parameter that defaults to `Telemetry.noop`. Existing callers
keep working without changes; callers that want metrics pass in a
real `Telemetry`.

## User Scenarios

### US1 — Coordinator records round metrics (P1)

A test runs one round with N submissions, M deliveries, and K
total drops across the mixer chain. After
`Coordinator.runRound(...)`, the configured telemetry shows:

- `mixnet.round.submissions = N`
- `mixnet.round.deliveries = M`
- `mixnet.round.drops` histogram: one value per round (K total)
- `mixnet.round.drops_per_mixer.{0..mixerCount-1}` counters: each
  hop's drop count

### US2 — Mailroom records deposit / retrieve activity (P1)

After 5 deposits and 1 retrieve:

- `mailroom.deposit.accepted` counter: 5
- `mailroom.deposit.rejected` counter: 0
- `mailroom.retrieve.envelopes_returned` histogram: one entry per
  retrieve call

### US3 — Pkg records identity issuance (P2)

After issuing 3 distinct identities and one duplicate:

- `pkg.identity.issued` counter: 3
- `pkg.identity.rejected_duplicate` counter: 1

### Edge cases

- Components default to `Telemetry.noop`; existing tests using the
  no-telemetry constructor stay green without modification.
- `noop` recording incurs no allocations beyond the existing call
  pattern (single method call to a no-op singleton).

## Functional Requirements

- **FR-001**: `Coordinator.runRound` MUST accept an optional
  `Telemetry` parameter, defaulting to `Telemetry.noop`. On each
  call, MUST record the three metrics enumerated under US1.
- **FR-002**: `Mailroom.inMemory(ttlMs, telemetry)` and
  `Mailroom.persistent(path, ttlMs, telemetry)` MUST accept an
  optional `Telemetry` argument and record per-operation
  metrics per US2.
- **FR-003**: `Pkg.create(rosterPublicKeys, rosterPrivateKeys,
  threshold, dst, initialMailboxId, telemetry)` MUST accept an
  optional `Telemetry` argument and record per-operation metrics
  per US3.
- **FR-004**: All metric names MUST follow the convention
  `<module>.<noun>.<verb_or_dimension>`.
- **FR-005**: Wiring MUST be backward-compatible — every existing
  test continues to compile without modification.

## Success Criteria

- **SC-001**: `Coordinator.runRound` with 5 submissions and 1
  forced-drop reports `submissions=5`, `deliveries=4`, and the
  drops histogram has one entry of value 1.
- **SC-002**: `Mailroom.inMemory(ttl, telemetry).deposit(env, 0)`
  ×3 then `retrieve(...)` ×1 reports
  `deposit.accepted=3`, `retrieve.envelopes_returned` histogram
  one entry of 3.
- **SC-003**: `Pkg` issuing 3 unique identities then 1 duplicate
  reports `identity.issued=3`, `identity.rejected_duplicate=1`.

## Out of scope

- OTEL exporter — separate spec.
- Wiring telemetry into `SiidaClient`, `AgentClient`,
  `ChatSession`, or `ConfigChain` — additive follow-ups; the
  three highest-value call sites land here first.
- Tags / labels (per-mailbox-id breakdowns etc.). The MVP records
  aggregated metrics only.
- Concurrent-safe telemetry — caller's responsibility for now.

## Dependencies

- 018 observability (`siida.observability.api.Telemetry`).
- 004 mixnet-server (`Coordinator`).
- 005 pkg-keybootstrap (`Pkg`).
- 009 async-delivery (`Mailroom`).
