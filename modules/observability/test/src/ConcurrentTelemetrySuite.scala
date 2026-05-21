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

import java.util.concurrent.{CountDownLatch, Executors, TimeUnit}
import munit.FunSuite
import siida.observability.api.Telemetry

final class ConcurrentTelemetrySuite extends FunSuite:

  private def runOn(n: Int)(body: => Unit): Unit =
    val pool  = Executors.newFixedThreadPool(n)
    val start = CountDownLatch(1)
    val done  = CountDownLatch(n)
    (0 until n).foreach { _ =>
      pool.submit(new Runnable {
        def run(): Unit =
          start.await()
          try body finally done.countDown()
      })
    }
    start.countDown()
    done.await(30, TimeUnit.SECONDS)
    pool.shutdown()
    pool.awaitTermination(5, TimeUnit.SECONDS)

  test("SC-001: 8 threads × 1000 counter increments sums to 8000") {
    val t = Telemetry.concurrent()
    runOn(8) {
      var i = 0
      while i < 1000 do
        t.incrementCounter("c", 1L)
        i += 1
    }
    assertEquals(t.snapshot().counters("c"), 8000L)
  }

  test("SC-002: 8 threads × 1000 histogram records yields 8000 entries (any order)") {
    val t = Telemetry.concurrent()
    runOn(8) {
      var i = 0
      while i < 1000 do
        t.recordHistogram("h", 1.0)
        i += 1
    }
    assertEquals(t.snapshot().histograms("h").length, 8000)
  }

  test("SC-003: sequential single-thread use matches inMemory semantics") {
    val t = Telemetry.concurrent()
    t.incrementCounter("a", 1L)
    t.incrementCounter("a", 4L)
    t.recordGauge("g", 99.5)
    t.recordHistogram("h", 1.0)
    t.recordHistogram("h", 2.0)
    val s = t.snapshot()
    assertEquals(s.counters("a"), 5L)
    assertEquals(s.gauges("g"), 99.5)
    assertEquals(s.histograms("h").length, 2)
  }

  test("gauge under contention: snapshot returns one of the written values") {
    val t = Telemetry.concurrent()
    runOn(4) {
      var i = 0
      while i < 1000 do
        t.recordGauge("g", i.toDouble)
        i += 1
    }
    val v = t.snapshot().gauges("g")
    assert(v >= 0.0 && v <= 999.0, s"gauge value $v outside writer range")
  }

  test("snapshot does not block writers (live reads while writers run)") {
    val t = Telemetry.concurrent()
    val pool = Executors.newFixedThreadPool(4)
    val keepGoing = new java.util.concurrent.atomic.AtomicBoolean(true)
    (0 until 3).foreach { _ =>
      pool.submit(new Runnable {
        def run(): Unit =
          while keepGoing.get() do t.incrementCounter("c", 1L)
      })
    }
    // Take 50 snapshots while the writers are running
    val readSamples = (0 until 50).map { _ =>
      val s = t.snapshot()
      Thread.`yield`()
      s.counters.getOrElse("c", 0L)
    }
    keepGoing.set(false)
    pool.shutdown()
    pool.awaitTermination(5, TimeUnit.SECONDS)
    // Snapshots should be monotonically non-decreasing
    val pairs = readSamples.zip(readSamples.tail)
    val nonDecreasing = pairs.forall((a, b) => a <= b)
    assert(nonDecreasing, s"snapshots not monotonic: $readSamples")
  }
