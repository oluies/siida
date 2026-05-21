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

import io.opentelemetry.api.metrics.{DoubleGauge, DoubleHistogram, LongCounter, Meter}

/** OpenTelemetry-bridge `Telemetry` (spec 022). Single-threaded —
 *  the local instrument cache is a plain HashMap. OTEL's `Meter`
 *  itself is thread-safe.
 *
 *  Privacy contract: only metric names that match the
 *  `allowedMetrics` set reach the OTEL sink. The allowlist exists
 *  because Siida's threat model (constitution v2.0.0 Principle I)
 *  forbids per-participant metadata in exported telemetry; this is
 *  the enforcement boundary.
 */
private[api] final class OtelTelemetry(
  meter:          Meter,
  allowedMetrics: Set[String],
) extends Telemetry:

  // Pre-compute the prefix matchers from `*`-suffixed entries.
  private val (exactNames, prefixMatchers) =
    val (globs, exacts) = allowedMetrics.partition(_.endsWith("*"))
    (exacts, globs.map(_.stripSuffix("*")))

  // Instrument caches — lazy creation on first record per name.
  private val counters   = scala.collection.mutable.HashMap.empty[String, LongCounter]
  private val gauges     = scala.collection.mutable.HashMap.empty[String, DoubleGauge]
  private val histograms = scala.collection.mutable.HashMap.empty[String, DoubleHistogram]

  private def allowed(name: String): Boolean =
    exactNames.contains(name) || prefixMatchers.exists(name.startsWith)

  def incrementCounter(name: String, by: Long): Unit =
    if allowed(name) then
      counters.getOrElseUpdate(name, meter.counterBuilder(name).build()).add(by)

  def recordGauge(name: String, value: Double): Unit =
    if allowed(name) then
      gauges.getOrElseUpdate(name, meter.gaugeBuilder(name).build()).set(value)

  def recordHistogram(name: String, value: Double): Unit =
    if allowed(name) then
      histograms.getOrElseUpdate(name, meter.histogramBuilder(name).build()).record(value)

  def snapshot(): Telemetry.Snapshot =
    // The OTEL exporter doesn't retain values locally — the SDK
    // (configured by the caller) is the source of truth.
    Telemetry.Snapshot(Map.empty, Map.empty, Map.empty)


object OtelTelemetry:

  /** Conservative default allowlist matching the constitution's
   *  "aggregate counters bucketed at the round level" wording.
   *
   *  Notably EXCLUDED:
   *  - `mixnet.round.drops` (per-round histogram — borderline per
   *    021 review)
   *  - `mixnet.round.drops_per_mixer.*` (per-hop dimension —
   *    available on the in-process `RoundMetrics` return value)
   *  - `mailroom.retrieve.envelopes_returned` (per-retrieve
   *    histogram — recipient-activity fingerprint risk)
   *
   *  Callers who need those for ops dashboards opt-in explicitly,
   *  e.g. `SafeDefaults ++ Set("mixnet.round.drops_per_mixer.*")`.
   */
  val SafeDefaults: Set[String] = Set(
    "mixnet.round.submissions",
    "mixnet.round.deliveries",
    "mailroom.deposit.accepted",
    "mailroom.deposit.rejected",
    "mailroom.backlog",
    "pkg.identity.issued",
    "pkg.identity.rejected_duplicate",
    "pkg.directory.size",
  )
