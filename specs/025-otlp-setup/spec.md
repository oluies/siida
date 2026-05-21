# Feature Specification: OTLP Exporter Wiring

**Feature Branch**: `025-otlp-setup`

**Created**: 2026-05-21

**Status**: Draft (MVP)

## Why this spec exists

Spec 022 ships `Telemetry.otel(meter, allowedMetrics)` that bridges
recordings to a caller-supplied `Meter` — but the caller has to
build the `Meter` themselves, which requires knowing the
`SdkMeterProvider` + exporter wiring incantation. This spec adds
a one-call helper that returns a `(Meter, AutoCloseable)` for the
common OTLP/HTTP case.

The OTLP exporter library is the standard way to ship metrics to
any OpenTelemetry collector (Prometheus, Jaeger, Tempo, vendor
backends). Adding the wiring here means operators get drop-in
"point at your collector and go" deployment without writing
OTEL boilerplate.

## User Scenarios

### US1 — Set up OTLP/HTTP export against a local collector (P1)

```scala
val (meter, close) = OtelSetup.otlpHttp(
  endpoint           = "http://localhost:4318",
  serviceName        = "siida-mixer-1",
  exportIntervalMs   = 10_000,
  instrumentationName = "siida",
)
val tel = Telemetry.otel(meter, OtelTelemetry.SafeDefaults)
// ... use tel ...
close.close()
```

The factory builds an `SdkMeterProvider` with a
`PeriodicMetricReader` driven by an
`OtlpHttpMetricExporter`, registers the named service resource,
and returns the `Meter` + a closeable that flushes + shuts down
the provider on close.

### US2 — Graceful shutdown (P1)

`close.close()` MUST trigger a final flush of pending metrics and
then shut the provider down. Idempotent — calling close twice is
a no-op.

### Edge cases

- Endpoint is not reachable: the exporter logs at WARN through
  OTEL's internal logger; recordings still succeed locally, just
  don't reach the collector. (OTEL's chosen behaviour; we don't
  intercept.)
- Service name MUST NOT be empty — fail fast with
  `IllegalArgumentException` at construction.

## Functional Requirements

- **FR-001**: `OtelSetup.otlpHttp(endpoint, serviceName,
  exportIntervalMs, instrumentationName)` MUST return a
  `(Meter, AutoCloseable)` tuple.
- **FR-002**: Constructed provider MUST tag the OTEL `Resource`
  with `service.name = <serviceName>`.
- **FR-003**: `close.close()` MUST call
  `SdkMeterProvider.shutdown()` and block until completion (or a
  timeout — OTEL handles).
- **FR-004**: Empty service name MUST throw
  `IllegalArgumentException` (FR-002's tag would be meaningless).

## Success Criteria

- **SC-001**: A constructed meter accepts recordings without
  throwing.
- **SC-002**: Closing the returned `AutoCloseable` doesn't throw
  and is idempotent.
- **SC-003**: Service-name validation: empty string throws.

## Out of scope

- gRPC OTLP variant — HTTP/protobuf only for the MVP (HTTPS
  setup is the caller's responsibility via standard JVM truststore).
- Auto-detected exporter config via OTEL env vars — caller
  supplies args directly.
- Trace / log exporters — metrics only.

## Dependency added

- `io.opentelemetry:opentelemetry-exporter-otlp:1.43.0`
  - Apache-2.0; transitive deps via OTEL's BOM include
    OkHttp + Protobuf. All Apache-2.0.

## Dependencies

- 018 + 022 (`Telemetry` trait + `OtelTelemetry`).
