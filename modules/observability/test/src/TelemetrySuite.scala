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

import munit.FunSuite
import siida.observability.api.Telemetry

final class TelemetrySuite extends FunSuite:

  test("SC-001: counter incremented 100× reports 100") {
    val t = Telemetry.inMemory()
    (0 until 100).foreach(_ => t.incrementCounter("m", 1L))
    assertEquals(t.snapshot().counters("m"), 100L)
  }

  test("SC-002: gauge is last-wins") {
    val t = Telemetry.inMemory()
    t.recordGauge("g", 1.0)
    t.recordGauge("g", 2.0)
    t.recordGauge("g", 3.0)
    assertEquals(t.snapshot().gauges("g"), 3.0)
  }

  test("SC-003: histogram preserves insertion order") {
    val t = Telemetry.inMemory()
    Vector(1.0, 2.0, 3.0).foreach(v => t.recordHistogram("h", v))
    assertEquals(t.snapshot().histograms("h"), Vector(1.0, 2.0, 3.0))
  }

  test("SC-004: noop snapshot is always empty") {
    val t = Telemetry.noop
    t.incrementCounter("x", 5L)
    t.recordGauge("y", 99.0)
    t.recordHistogram("z", 1.0)
    val s = t.snapshot()
    assertEquals(s.counters, Map.empty[String, Long])
    assertEquals(s.gauges, Map.empty[String, Double])
    assertEquals(s.histograms, Map.empty[String, Vector[Double]])
  }

  test("multiple counters track independently") {
    val t = Telemetry.inMemory()
    t.incrementCounter("a", 1L)
    t.incrementCounter("b", 5L)
    t.incrementCounter("a", 2L)
    val c = t.snapshot().counters
    assertEquals(c("a"), 3L)
    assertEquals(c("b"), 5L)
  }

  test("snapshot is immutable to subsequent recordings") {
    val t = Telemetry.inMemory()
    t.incrementCounter("c", 1L)
    val s1 = t.snapshot()
    t.incrementCounter("c", 1L)
    assertEquals(s1.counters("c"), 1L)
    assertEquals(t.snapshot().counters("c"), 2L)
  }
