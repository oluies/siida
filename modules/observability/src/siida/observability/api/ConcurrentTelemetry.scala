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

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.{AtomicReference, LongAdder}

/** Concurrent-safe in-memory `Telemetry` (spec 024). No global
 *  lock — writers contend per-metric on JDK atomics; snapshot
 *  reads don't block writers.
 *
 *  Eventually consistent: a snapshot taken during concurrent
 *  recording captures values present at the moment of read; later
 *  writes appear in the next snapshot.
 */
private[api] final class ConcurrentTelemetry extends Telemetry:

  private val counters   = new ConcurrentHashMap[String, LongAdder]()
  private val gauges     = new ConcurrentHashMap[String, AtomicReference[java.lang.Double]]()
  private val histograms = new ConcurrentHashMap[String, ConcurrentLinkedQueue[java.lang.Double]]()

  def incrementCounter(name: String, by: Long): Unit =
    counters.computeIfAbsent(name, _ => new LongAdder()).add(by)

  def recordGauge(name: String, value: Double): Unit =
    gauges
      .computeIfAbsent(name, _ => new AtomicReference[java.lang.Double](java.lang.Double.valueOf(0.0)))
      .set(java.lang.Double.valueOf(value))

  def recordHistogram(name: String, value: Double): Unit =
    histograms
      .computeIfAbsent(name, _ => new ConcurrentLinkedQueue[java.lang.Double]())
      .add(java.lang.Double.valueOf(value))

  def snapshot(): Telemetry.Snapshot =
    // Copy-out semantics. Counters / gauges: read each atomic once.
    // Histograms: iterate snapshot of the queue (toArray is atomic
    // wrt queue state at the call boundary, per the ConcurrentLinked
    // Queue contract).
    val countersMap: Map[String, Long] =
      val b = Map.newBuilder[String, Long]
      counters.forEach { (k, v) => b += k -> v.sum() }
      b.result()
    val gaugesMap: Map[String, Double] =
      val b = Map.newBuilder[String, Double]
      gauges.forEach { (k, v) => b += k -> v.get().doubleValue() }
      b.result()
    val histogramsMap: Map[String, Vector[Double]] =
      val b = Map.newBuilder[String, Vector[Double]]
      histograms.forEach { (k, v) =>
        val arr = v.toArray(new Array[java.lang.Double](0))
        b += k -> arr.iterator.map(_.doubleValue()).toVector
      }
      b.result()
    Telemetry.Snapshot(countersMap, gaugesMap, histogramsMap)
