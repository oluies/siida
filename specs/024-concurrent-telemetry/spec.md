# Feature Specification: Concurrent-Safe Telemetry

**Feature Branch**: `024-concurrent-telemetry`

**Created**: 2026-05-21

**Status**: Draft (MVP)

## Why this spec exists

Spec 018's `Telemetry.inMemory()` is single-threaded — the trait
docs say so explicitly. In production, Coordinator (spec 004) runs
on Pekko Streams and PKG / Mailroom may be invoked from multiple
fibers. A drop-in concurrent-safe variant means call sites don't
need to add their own synchronisation around `Telemetry`
recordings.

This spec adds `Telemetry.concurrent()` backed by JDK 21's
`java.util.concurrent.atomic.LongAdder` (counters),
`AtomicReference[Double]` (gauges), and a `ConcurrentLinkedQueue`
(histograms). Snapshot semantics are eventually-consistent: a
snapshot taken during concurrent recording captures values
read at the moment of the call (no global lock; readers and
writers don't block each other).

## User Scenarios

### US1 — Concurrent counter increments (P1)

`Telemetry.concurrent()` accepts N threads incrementing the same
counter 1000 times each. `snapshot().counters("c")` after all
threads complete returns `N × 1000`.

### US2 — Concurrent gauge writes (P1)

Multiple threads writing the same gauge concurrently; the snapshot
returns *some* value the writers wrote (last-writer-wins under
concurrent reads is acceptable; the read ordering is not guaranteed).

### US3 — Concurrent histogram appends (P1)

Multiple threads recording into the same histogram; the snapshot
returns all values (sum of N×K entries) but in no guaranteed order.

### US4 — Snapshot doesn't block writers (P2)

Calling `snapshot()` while writers are active does not block them.
The snapshot may miss recordings that happened concurrently — by
design, eventually-consistent.

### Edge cases

- Snapshot during high write rate: may include a partial set of
  histogram values (drained from the queue at snapshot time, then
  the queue is re-populated by subsequent writes).
- A reader that wants a stable "epoch" of values is the caller's
  problem — the MVP doesn't ship a `pause-and-snapshot` operation.

## Functional Requirements

- **FR-001**: `Telemetry.concurrent()` MUST return a thread-safe
  `Telemetry` instance.
- **FR-002**: Counters MUST use `LongAdder` (high-contention safe).
- **FR-003**: Gauges MUST use atomic reference semantics — readers
  see one of the values a writer set (no torn reads).
- **FR-004**: Histograms MUST preserve all recorded values
  (no loss under concurrency). Order is not guaranteed.
- **FR-005**: `snapshot()` MUST NOT acquire a lock that blocks
  writers.

## Success Criteria

- **SC-001**: 8 threads × 1000 increments to a shared counter
  results in `snapshot().counters(name) == 8000`.
- **SC-002**: 8 threads × 1000 histogram records yields a snapshot
  histogram of length 8000.
- **SC-003**: Snapshot is sensibly correct under sequential use
  (matches the `inMemory()` semantics for a single thread).

## Out of scope

- Wiring the concurrent variant into existing call sites — additive
  optional API; callers pick which impl based on their threading.
- A pause-and-snapshot atomicity guarantee.
- Tags / labels (still deferred).

## Dependencies

- 018 observability (the existing `Telemetry` trait).
