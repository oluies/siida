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

package siida.observability

import scala.jdk.CollectionConverters.*
import io.opentelemetry.sdk.metrics.SdkMeterProvider
import io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader
import munit.FunSuite
import siida.observability.api.{OtelTelemetry, Telemetry}

/** Spec 022 — OTEL exporter delegates allowed metrics + drops the
 *  rest by default.
 */
final class OtelTelemetrySuite extends FunSuite:

  private def mkReader(): (Telemetry, InMemoryMetricReader, () => Unit) =
    val reader   = InMemoryMetricReader.create()
    val provider = SdkMeterProvider.builder().registerMetricReader(reader).build()
    val meter    = provider.get("siida.test")
    val tel      = Telemetry.otel(meter, OtelTelemetry.SafeDefaults)
    (tel, reader, () => provider.close())

  private def counterValue(reader: InMemoryMetricReader, name: String): Option[Long] =
    val metrics = reader.collectAllMetrics().asScala.toVector
    metrics.find(_.getName == name).flatMap { m =>
      m.getLongSumData.getPoints.asScala.headOption.map(_.getValue)
    }

  private def gaugeValue(reader: InMemoryMetricReader, name: String): Option[Double] =
    val metrics = reader.collectAllMetrics().asScala.toVector
    metrics.find(_.getName == name).flatMap { m =>
      m.getDoubleGaugeData.getPoints.asScala.headOption.map(_.getValue)
    }

  test("SC-001: allowed counter is delegated through OTEL SDK") {
    val (tel, reader, close) = mkReader()
    try
      tel.incrementCounter("mixnet.round.submissions", 5L)
      assertEquals(counterValue(reader, "mixnet.round.submissions"), Some(5L))
    finally close()
  }

  test("SC-002: per-round histogram NOT exported under SafeDefaults") {
    val (tel, reader, close) = mkReader()
    try
      tel.recordHistogram("mixnet.round.drops", 3.0)
      val names = reader.collectAllMetrics().asScala.map(_.getName).toSet
      assert(!names.contains("mixnet.round.drops"),
        s"per-round histogram leaked through SafeDefaults allowlist: $names")
    finally close()
  }

  test("SC-003: opting into per-mixer prefix glob admits the metric") {
    val reader   = InMemoryMetricReader.create()
    val provider = SdkMeterProvider.builder().registerMetricReader(reader).build()
    try
      val meter = provider.get("siida.test")
      val tel = Telemetry.otel(
        meter,
        OtelTelemetry.SafeDefaults ++ Set("mixnet.round.drops_per_mixer.*"),
      )
      tel.incrementCounter("mixnet.round.drops_per_mixer.0", 1L)
      tel.incrementCounter("mixnet.round.drops_per_mixer.1", 2L)
      assertEquals(counterValue(reader, "mixnet.round.drops_per_mixer.0"), Some(1L))
      assertEquals(counterValue(reader, "mixnet.round.drops_per_mixer.1"), Some(2L))
    finally provider.close()
  }

  test("unlisted metric name silently dropped (no exception, no export)") {
    val (tel, reader, close) = mkReader()
    try
      tel.incrementCounter("siida.unknown.metric", 99L)
      assertEquals(counterValue(reader, "siida.unknown.metric"), None)
    finally close()
  }

  test("instrument cache reuses the same OTEL counter across calls") {
    val (tel, reader, close) = mkReader()
    try
      tel.incrementCounter("mixnet.round.submissions", 3L)
      tel.incrementCounter("mixnet.round.submissions", 4L)
      // Cumulative sum semantics: 7
      assertEquals(counterValue(reader, "mixnet.round.submissions"), Some(7L))
    finally close()
  }

  test("gauge: last-wins through OTEL") {
    val (tel, reader, close) = mkReader()
    try
      tel.recordGauge("mailroom.backlog", 1.0)
      tel.recordGauge("mailroom.backlog", 42.0)
      assertEquals(gaugeValue(reader, "mailroom.backlog"), Some(42.0))
    finally close()
  }

  test("OtelTelemetry.snapshot is always empty (OTEL SDK owns the state)") {
    val (tel, _, close) = mkReader()
    try
      tel.incrementCounter("mixnet.round.submissions", 1L)
      tel.recordGauge("mailroom.backlog", 9.0)
      val s = tel.snapshot()
      assertEquals(s.counters, Map.empty[String, Long])
      assertEquals(s.gauges, Map.empty[String, Double])
      assertEquals(s.histograms, Map.empty[String, Vector[Double]])
    finally close()
  }
