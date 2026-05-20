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
   *  for not concurrently invoking the methods. A concurrent variant
   *  is a follow-up spec.
   */
  def inMemory(): Telemetry = new InMemoryTelemetry()

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
