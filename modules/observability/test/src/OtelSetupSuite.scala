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
import siida.observability.api.{OtelSetup, OtelTelemetry, Telemetry}

/** Spec 025 — OtelSetup.otlpHttp builds a usable Meter + closer. */
final class OtelSetupSuite extends FunSuite:

  test("SC-001: constructed meter accepts recordings without throwing") {
    val (meter, close) = OtelSetup.otlpHttp(
      endpoint            = "http://localhost:14318", // unreachable port; OTEL just logs
      serviceName         = "siida-test",
      exportIntervalMs    = 60_000L,                  // long interval; we close before it fires
      instrumentationName = "siida",
    )
    try
      val tel = Telemetry.otel(meter, OtelTelemetry.SafeDefaults)
      tel.incrementCounter("mixnet.round.submissions", 1L)
      tel.recordGauge("mailroom.backlog", 7.0)
      // no exception = pass
    finally close.close()
  }

  test("SC-002: closer is idempotent") {
    val (_, close) = OtelSetup.otlpHttp(
      endpoint            = "http://localhost:14319",
      serviceName         = "siida-test",
      exportIntervalMs    = 60_000L,
      instrumentationName = "siida",
    )
    close.close()
    close.close() // must not throw
  }

  test("SC-003: empty serviceName throws IllegalArgumentException") {
    intercept[IllegalArgumentException] {
      OtelSetup.otlpHttp(
        endpoint            = "http://localhost:14320",
        serviceName         = "",
        exportIntervalMs    = 1_000L,
        instrumentationName = "siida",
      )
    }
  }

  test("empty instrumentationName throws") {
    intercept[IllegalArgumentException] {
      OtelSetup.otlpHttp(
        endpoint            = "http://localhost:14321",
        serviceName         = "siida-test",
        exportIntervalMs    = 1_000L,
        instrumentationName = "",
      )
    }
  }

  test("non-positive exportIntervalMs throws") {
    intercept[IllegalArgumentException] {
      OtelSetup.otlpHttp(
        endpoint            = "http://localhost:14322",
        serviceName         = "siida-test",
        exportIntervalMs    = 0L,
        instrumentationName = "siida",
      )
    }
  }
