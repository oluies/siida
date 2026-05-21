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

/** Telemetry abstraction for Siida operations (spec 018 MVP).
 *
 *  In-process, thread-unsafe, no external deps. A future spec wires
 *  an OpenTelemetry exporter as a separate implementation of this
 *  same trait so call sites don't change.
 */
trait Telemetry:

  def incrementCounter(name: String, by: Long): Unit

  def recordGauge(name: String, value: Double): Unit

  def recordHistogram(name: String, value: Double): Unit

  def snapshot(): Telemetry.Snapshot


object Telemetry:

  /** Frozen point-in-time view of the telemetry state. */
  final case class Snapshot(
    counters:   Map[String, Long],
    gauges:     Map[String, Double],
    histograms: Map[String, Vector[Double]],
  )

  /** No-op telemetry: every call is silently discarded. Useful for
   *  code paths that don't care about metrics (tests, paths where
   *  telemetry is disabled by config).
   */
  val noop: Telemetry = new Telemetry:
    def incrementCounter(name: String, by: Long): Unit       = ()
    def recordGauge(name: String, value: Double): Unit       = ()
    def recordHistogram(name: String, value: Double): Unit   = ()
    def snapshot(): Snapshot                                 = Snapshot(Map.empty, Map.empty, Map.empty)

  /** Single-threaded in-memory telemetry. The caller is responsible
   *  for not concurrently invoking the methods. For multi-thread
   *  use, see [[concurrent]] (spec 024).
   */
  def inMemory(): Telemetry = new InMemoryTelemetry()

  /** Concurrent-safe in-memory telemetry (spec 024). Multiple
   *  threads may freely record; snapshot reads do not block writers
   *  (eventually-consistent).
   *
   *  Counters use `LongAdder` for high-contention throughput;
   *  gauges use atomic reference semantics; histograms append into
   *  a `ConcurrentLinkedQueue`. Snapshots drain & re-populate
   *  histograms via copy-out — see implementation comments.
   */
  def concurrent(): Telemetry = new ConcurrentTelemetry()

  /** OpenTelemetry-bridge telemetry (spec 022). Delegates each
   *  recording to a caller-supplied `Meter`, gated by a privacy
   *  allowlist applied at the exporter boundary.
   *
   *  See [[OtelTelemetry.SafeDefaults]] for the conservative
   *  default allowlist (constitution-compatible "aggregate
   *  counters bucketed at the round level").
   *
   *  Metric names ending in `*` in the allowlist match by prefix
   *  (e.g. `mixnet.round.drops_per_mixer.*` matches
   *  `mixnet.round.drops_per_mixer.0`). All other names are
   *  silently discarded — the OTEL sink only sees what the
   *  caller has explicitly opted in.
   */
  def otel(
    meter:          io.opentelemetry.api.metrics.Meter,
    allowedMetrics: Set[String],
  ): Telemetry =
    new OtelTelemetry(meter, allowedMetrics)

  private final class InMemoryTelemetry extends Telemetry:
    private val counters   = scala.collection.mutable.HashMap.empty[String, Long]
    private val gauges     = scala.collection.mutable.HashMap.empty[String, Double]
    private val histograms = scala.collection.mutable.HashMap.empty[String, scala.collection.mutable.ArrayBuffer[Double]]

    def incrementCounter(name: String, by: Long): Unit =
      counters.update(name, counters.getOrElse(name, 0L) + by)

    def recordGauge(name: String, value: Double): Unit =
      gauges.update(name, value)

    def recordHistogram(name: String, value: Double): Unit =
      histograms.getOrElseUpdate(name, scala.collection.mutable.ArrayBuffer.empty[Double]) += value

    def snapshot(): Snapshot =
      Snapshot(
        counters   = counters.toMap,
        gauges     = gauges.toMap,
        histograms = histograms.iterator.map { (k, v) => (k, v.toVector) }.toMap,
      )
