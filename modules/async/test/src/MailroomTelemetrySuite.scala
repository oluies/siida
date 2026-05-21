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

package siida.async

import java.nio.file.Files
import munit.FunSuite
import siida.async.api.Mailroom
import siida.mixnet.api.MixChain
import siida.observability.api.Telemetry

/** Spec 021 — Mailroom records deposit/retrieve activity. */
final class MailroomTelemetrySuite extends FunSuite:

  private def envFor(id: Long, payload: Array[Byte]): MixChain.MailboxEnvelope =
    MixChain.envelope(id, payload)

  test("SC-002: in-memory deposit×3 + retrieve×1 records the expected metrics") {
    val tel = Telemetry.inMemory()
    val m = Mailroom.inMemory(60_000L, tel)
    assertEquals(m.deposit(envFor(10L, "a".getBytes("UTF-8")), 0L), true)
    assertEquals(m.deposit(envFor(10L, "b".getBytes("UTF-8")), 0L), true)
    assertEquals(m.deposit(envFor(10L, "c".getBytes("UTF-8")), 0L), true)
    val out = m.retrieve(10L, 0L)
    assertEquals(out.length, 3)
    val s = tel.snapshot()
    assertEquals(s.counters("mailroom.deposit.accepted"), 3L)
    assertEquals(s.counters.getOrElse("mailroom.deposit.rejected", 0L), 0L)
    assertEquals(s.histograms("mailroom.retrieve.envelopes_returned"), Vector(3.0))
    // Final backlog gauge after retrieve = 0
    assertEquals(s.gauges("mailroom.backlog"), 0.0)
  }

  test("in-memory: deposits to cover/broadcast mailboxes increment rejected counter") {
    val tel = Telemetry.inMemory()
    val m = Mailroom.inMemory(60_000L, tel)
    assertEquals(m.deposit(envFor(MixChain.CoverMailboxId, "x".getBytes("UTF-8")), 0L), false)
    assertEquals(m.deposit(envFor(MixChain.BroadcastMailboxId, "y".getBytes("UTF-8")), 0L), false)
    val s = tel.snapshot()
    assertEquals(s.counters("mailroom.deposit.rejected"), 2L)
    assertEquals(s.counters.getOrElse("mailroom.deposit.accepted", 0L), 0L)
  }

  test("persistent mailroom records the same metrics") {
    val path = Files.createTempFile("siida-mr-tel-", ".simr")
    val tel = Telemetry.inMemory()
    val m = Mailroom.persistent(path, 60_000L, tel).toOption.get
    assertEquals(m.deposit(envFor(2L, "p".getBytes("UTF-8")), 0L), true)
    val out = m.retrieve(2L, 0L)
    assertEquals(out.length, 1)
    val s = tel.snapshot()
    assertEquals(s.counters("mailroom.deposit.accepted"), 1L)
    assertEquals(s.histograms("mailroom.retrieve.envelopes_returned"), Vector(1.0))
  }
