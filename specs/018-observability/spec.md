# Feature Specification: Observability (MVP)

**Feature Branch**: `018-observability`

**Created**: 2026-05-20

**Status**: Draft (MVP — abstraction + in-memory + no-op)

## Why this spec exists

Operators of a deployed Siida instance need to know:
- mixnet round throughput (submissions in / deliveries out)
- per-mixer drop counts (silent-fail submissions)
- mailroom backlog size
- PKG identity issuance rate

The README sketches "OpenTelemetry, ops dashboards." A full
OTEL wire-up requires a non-trivial dependency add (constitution
v1.0.0 stack-line decision). This MVP ships the **abstraction**
plus an in-memory implementation that callers can use today; a
follow-up spec wires the OTEL exporter as a separate
implementation behind the same trait.

## User Scenarios

### US1 — Counter (P1)

`telemetry.incrementCounter("mixnet.round.submissions", 1)` records
+1 to that counter. `telemetry.snapshot()` returns a `Snapshot`
that includes the current counter values.

### US2 — Gauge (P1)

`telemetry.recordGauge("mailroom.backlog", N)` overwrites the
current value of that gauge. Snapshot reads the last-recorded.

### US3 — Histogram (P2)

`telemetry.recordHistogram("round.duration_ms", v)` appends `v` to
a per-name histogram. Snapshot returns the recorded values; the
caller can compute percentiles.

### US4 — No-op implementation (P1)

`Telemetry.noop` is a singleton that ignores every call. Useful
for code paths that don't care about metrics (tests, hot paths
when telemetry is disabled).

### Edge cases

- Names are arbitrary strings; the MVP does no validation.
- Tag/label support is **not** in the MVP — tags would require a
  schema decision (OTEL attributes vs. Prometheus labels) deferred
  to the OTEL-wiring spec.

## Functional Requirements

- **FR-001**: `Telemetry` MUST expose `incrementCounter`,
  `recordGauge`, `recordHistogram`, and `snapshot`.
- **FR-002**: `Telemetry.inMemory()` MUST return a thread-unsafe
  in-process telemetry — single-threaded discipline is the caller's
  responsibility. (Concurrent variant is a follow-up.)
- **FR-003**: `Telemetry.noop` MUST be a singleton that silently
  discards every recording.
- **FR-004**: `Snapshot` MUST expose `counters: Map[String, Long]`,
  `gauges: Map[String, Double]`, `histograms: Map[String, Vector[Double]]`.

## Success Criteria

- **SC-001**: A counter incremented 100 times reports 100 in the
  snapshot.
- **SC-002**: A gauge recorded with values 1.0, 2.0, 3.0 reports
  3.0 (last-wins semantics).
- **SC-003**: A histogram receiving values [1, 2, 3] returns the
  vector [1, 2, 3] in insertion order.
- **SC-004**: `Telemetry.noop`'s snapshot is empty regardless of
  how many recordings were attempted.

## Out of scope

- OpenTelemetry exporter (separate follow-up).
- Concurrent recording (follow-up).
- Sampling / aggregation / windowing.
- Distributed tracing (spans / context propagation).
- Wiring into existing modules (Coordinator, Mixer, Mailroom, PKG).

## Dependencies

- None (pure in-process).
