# Feature Specification: OpenTelemetry Exporter for Telemetry

**Feature Branch**: `022-otel-exporter`

**Created**: 2026-05-21

**Status**: Draft (MVP)

## Why this spec exists

Specs 018 and 021 shipped the `Telemetry` abstraction with
in-memory + no-op implementations and wired it into Coordinator,
Mailroom, and Pkg. The README and 018's "scope deferred" list
called out an OpenTelemetry exporter as a future implementation
of the same trait. This spec ships that exporter.

Concrete deliverable: `Telemetry.otel(meter, allowedMetrics)` that
delegates recordings to a caller-supplied `io.opentelemetry.api`
`Meter` — and **applies a privacy allowlist** at the exporter
boundary so the round-resolution histograms (which the 021
review noted as borderline) are not exported by default. Only
metric names explicitly enumerated by the caller make it to the
external sink.

This is a constitution stack-line decision (a new external
dependency): `io.opentelemetry:opentelemetry-api`, Apache-2.0,
permitted under the project's licence allowlist.

## User Scenarios

### US1 — Caller wraps an existing `Meter` (P1)

Operator builds an OTEL `SdkMeterProvider` configured with their
preferred exporter (OTLP, Prometheus scrape, etc.) and pulls a
`Meter`. They construct
`Telemetry.otel(meter, allowedMetrics = OtelTelemetry.SafeDefaults)`
and pass it to `Coordinator.runRound(...)`. Counters and gauges
matching the allowlist appear in the SDK's reader.

### US2 — Privacy allowlist denies by default (P1)

`OtelTelemetry.SafeDefaults` includes only the constitution-
compatible "aggregate counters bucketed at the round level":

- `mixnet.round.submissions`
- `mixnet.round.deliveries`
- `mixnet.round.drops_total` (NEW — aggregated by the exporter from
  the per-mixer counters)
- `mailroom.deposit.accepted`
- `mailroom.deposit.rejected`
- `mailroom.backlog`
- `pkg.identity.issued`
- `pkg.identity.rejected_duplicate`
- `pkg.directory.size`

Per-round histograms (`mixnet.round.drops`,
`mailroom.retrieve.envelopes_returned`) and per-mixer counters
(`mixnet.round.drops_per_mixer.*`) are NOT in the default
allowlist — they remain available on the in-process `RoundMetrics`
return values and can still be recorded by other `Telemetry` impls
(e.g. `Telemetry.inMemory()` for tests), but the OTEL exporter
silently drops them.

### US3 — Caller widens the allowlist explicitly (P2)

A caller who wants per-mixer drops for ops dashboards passes
`OtelTelemetry.SafeDefaults ++ Set("mixnet.round.drops_per_mixer.*")`.
The `*` is a literal-suffix glob: any metric name starting with
that prefix matches.

### Edge cases

- `incrementCounter("mixnet.round.drops_per_mixer.5", 3)` with the
  default allowlist: dropped silently.
- An unknown metric name: dropped silently (no warning — the caller
  may legitimately have many call sites the operator hasn't
  enumerated).
- OTEL's `LongCounter` / `DoubleGauge` / `DoubleHistogram` are
  created lazily on first record and cached in a HashMap by
  metric name (avoid the per-call instrument-create overhead).

## Functional Requirements

- **FR-001**: `Telemetry.otel(meter, allowedMetrics)` MUST exist as
  a factory on the existing `Telemetry` companion and return a
  `Telemetry` instance.
- **FR-002**: `OtelTelemetry.SafeDefaults: Set[String]` MUST be the
  conservative allowlist enumerated in US2 above.
- **FR-003**: Recordings whose metric name is NOT in the allowlist
  MUST be silently discarded (no exception, no log warning, no
  instrument creation on the OTEL side).
- **FR-004**: Allowlist entries ending in `*` MUST match by
  prefix (without the `*`). Entries without `*` MUST match exactly.
- **FR-005**: Recording the same metric name twice MUST reuse the
  cached OTEL instrument (no per-call create).
- **FR-006**: `snapshot()` MUST return an empty `Snapshot` — the
  OTEL exporter doesn't retain values in-process (the SDK does).

## Success Criteria

- **SC-001**: `Telemetry.otel(meter, SafeDefaults).incrementCounter
  ("mixnet.round.submissions", 5L)` results in the OTEL SDK
  reporting a counter of value 5 under the same name.
- **SC-002**: `Telemetry.otel(meter, SafeDefaults).recordHistogram
  ("mixnet.round.drops", 3.0)` does NOT appear in the SDK reader
  (allowlist denies it).
- **SC-003**: `incrementCounter("mixnet.round.drops_per_mixer.0",
  1L)` with `SafeDefaults ++ Set("mixnet.round.drops_per_mixer.*")`
  appears as a counter of value 1.

## Out of scope

- Wiring up an OTLP / Prometheus exporter — caller's responsibility
  (the MVP just bridges `Telemetry` to a caller-supplied `Meter`).
- Tag/label support — still deferred (the trait surface doesn't
  expose tags; this spec adds the bridge, not new dimensions).
- Concurrent-safe `OtelTelemetry` — OTEL's `Meter` itself is
  thread-safe, but the local instrument-cache HashMap isn't.
  Single-writer discipline still applies.
- Replacing the per-round histograms in the in-process recordings
  — the existing call sites stay; this spec adds enforcement at the
  exporter boundary instead, addressing the 021 review note.

## Dependency added

- `io.opentelemetry:opentelemetry-api:1.43.0`
  - Apache-2.0; CNCF project; pinned MAJOR.MINOR.PATCH per FR-011.
- (Test only) `io.opentelemetry:opentelemetry-sdk-testing:1.43.0`
  - Apache-2.0; provides `InMemoryMetricReader` for assertions.

Both pulled in only by `modules.observability`. No transitive impact
on the `crypto`/`mixnet`/`pkg` modules (they continue to use the
`Telemetry` trait via 018's API surface).
