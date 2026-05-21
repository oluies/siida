// Siida — privacy-preserving messaging for human chat and AI-agent
// messaging. Derived from Vuvuzela (David Lazar et al., SOSP 2015) and
// the Alpenhorn key-bootstrap system.
//
// Copyright (C) 2026 Örjan Lundberg and contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see
// <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package siida.observability.api

import java.time.Duration
import io.opentelemetry.api.common.AttributeKey
import io.opentelemetry.api.metrics.Meter
import io.opentelemetry.exporter.otlp.http.metrics.OtlpHttpMetricExporter
import io.opentelemetry.sdk.metrics.SdkMeterProvider
import io.opentelemetry.sdk.metrics.`export`.PeriodicMetricReader
import io.opentelemetry.sdk.resources.Resource

/** One-call OTLP/HTTP wiring for the spec-022 `Telemetry.otel`
 *  bridge (spec 025).
 *
 *  Typical use:
 *  ```scala
 *  val (meter, close) = OtelSetup.otlpHttp(
 *    endpoint            = "http://localhost:4318",
 *    serviceName         = "siida-mixer-1",
 *    exportIntervalMs    = 10_000,
 *    instrumentationName = "siida",
 *  )
 *  val tel = Telemetry.otel(meter, OtelTelemetry.SafeDefaults)
 *  try { ... }
 *  finally close.close()
 *  ```
 */
object OtelSetup:

  /** Build an `SdkMeterProvider` with a periodic OTLP/HTTP
   *  exporter pointing at `endpoint`, and return its `Meter`
   *  + an `AutoCloseable` that flushes & shuts down the provider.
   *
   *  @param endpoint              OTLP collector base URL (e.g. "http://localhost:4318")
   *  @param serviceName           OTEL `service.name` resource attribute
   *  @param exportIntervalMs      how often (ms) the periodic reader pushes batches
   *  @param instrumentationName   passed to `MeterProvider.get(...)`; appears as
   *                                the OTEL `instrumentation.scope.name`
   */
  def otlpHttp(
    endpoint:            String,
    serviceName:         String,
    exportIntervalMs:    Long,
    instrumentationName: String,
  ): (Meter, AutoCloseable) =
    require(serviceName.nonEmpty, "OtelSetup.otlpHttp: serviceName must not be empty")
    require(instrumentationName.nonEmpty, "OtelSetup.otlpHttp: instrumentationName must not be empty")
    require(exportIntervalMs > 0L, s"OtelSetup.otlpHttp: exportIntervalMs must be > 0, got $exportIntervalMs")

    val exporter = OtlpHttpMetricExporter.builder()
      .setEndpoint(s"${endpoint.stripSuffix("/")}/v1/metrics")
      .build()

    val reader = PeriodicMetricReader.builder(exporter)
      .setInterval(Duration.ofMillis(exportIntervalMs))
      .build()

    val resource = Resource.builder()
      .put(AttributeKey.stringKey("service.name"), serviceName)
      .build()

    val provider = SdkMeterProvider.builder()
      .setResource(resource)
      .registerMetricReader(reader)
      .build()

    val meter = provider.get(instrumentationName)

    val closer: AutoCloseable = new AutoCloseable:
      private val closed = new java.util.concurrent.atomic.AtomicBoolean(false)
      def close(): Unit =
        if closed.compareAndSet(false, true) then
          provider.shutdown().join(10L, java.util.concurrent.TimeUnit.SECONDS)
          ()

    (meter, closer)
