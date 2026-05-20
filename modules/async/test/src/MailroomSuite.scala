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

final class MailroomSuite extends FunSuite:

  private def envFor(id: Long, payload: Array[Byte]): MixChain.MailboxEnvelope =
    MixChain.envelope(id, payload)

  // ── In-memory variant ─────────────────────────────────────────

  test("SC-001: deposit 3 across 2 mailboxes, retrieve one mailbox → only that mailbox's envelopes, in deposit order") {
    val m = Mailroom.inMemory(ttlMs = 60_000L)
    val e1 = envFor(10L, "a".getBytes("UTF-8"))
    val e2 = envFor(11L, "b".getBytes("UTF-8"))
    val e3 = envFor(10L, "c".getBytes("UTF-8"))
    assertEquals(m.deposit(e1, 0L), true)
    assertEquals(m.deposit(e2, 0L), true)
    assertEquals(m.deposit(e3, 0L), true)
    assertEquals(m.size, 3)

    val out10 = m.retrieve(10L, 0L)
    assertEquals(out10.length, 2)
    assertEquals(MixChain.envelopePayload(out10(0)).toSeq, "a".getBytes("UTF-8").toSeq)
    assertEquals(MixChain.envelopePayload(out10(1)).toSeq, "c".getBytes("UTF-8").toSeq)
    // mailbox 11 still pending
    assertEquals(m.size, 1)
    val out11 = m.retrieve(11L, 0L)
    assertEquals(out11.length, 1)
    assertEquals(m.size, 0)
  }

  test("SC-002: envelope deposited at t=0 with TTL=60s is dropped at retrieve(t=120s)") {
    val m = Mailroom.inMemory(ttlMs = 60_000L)
    val e = envFor(5L, "old".getBytes("UTF-8"))
    assertEquals(m.deposit(e, 0L), true)
    val out = m.retrieve(5L, 120_000L)
    assertEquals(out.length, 0)
    assertEquals(m.size, 0)
  }

  test("cover-traffic mailbox deposit is rejected (FR-001)") {
    val m = Mailroom.inMemory(ttlMs = 60_000L)
    val e = envFor(MixChain.CoverMailboxId, "noise".getBytes("UTF-8"))
    assertEquals(m.deposit(e, 0L), false)
    assertEquals(m.size, 0)
  }

  test("broadcast mailbox deposit is rejected") {
    val m = Mailroom.inMemory(ttlMs = 60_000L)
    val e = envFor(MixChain.BroadcastMailboxId, "bcast".getBytes("UTF-8"))
    assertEquals(m.deposit(e, 0L), false)
    assertEquals(m.size, 0)
  }

  test("retrieve from an empty mailbox returns empty") {
    val m = Mailroom.inMemory(ttlMs = 60_000L)
    assertEquals(m.retrieve(99L, 0L), Vector.empty)
  }

  // ── Persistent variant ────────────────────────────────────────

  test("SC-003: persistent mailroom round-trips envelopes across restart") {
    val path = Files.createTempFile("siida-mr-", ".simr")
    val m1 = Mailroom.persistent(path, ttlMs = 600_000L).toOption.get
    val e1 = envFor(7L, "alpha".getBytes("UTF-8"))
    val e2 = envFor(7L, "beta".getBytes("UTF-8"))
    assertEquals(m1.deposit(e1, 0L), true)
    assertEquals(m1.deposit(e2, 0L), true)

    val m2 = Mailroom.persistent(path, ttlMs = 600_000L).toOption.get
    val out = m2.retrieve(7L, 0L)
    assertEquals(out.length, 2)
    assertEquals(MixChain.envelopePayload(out(0)).toSeq, "alpha".getBytes("UTF-8").toSeq)
    assertEquals(MixChain.envelopePayload(out(1)).toSeq, "beta".getBytes("UTF-8").toSeq)
  }

  test("persistent mailroom: retrieve removes envelopes from on-disk state") {
    val path = Files.createTempFile("siida-mr-clr-", ".simr")
    val m1 = Mailroom.persistent(path, ttlMs = 600_000L).toOption.get
    assertEquals(m1.deposit(envFor(3L, "x".getBytes("UTF-8")), 0L), true)
    val _ = m1.retrieve(3L, 0L)
    val m2 = Mailroom.persistent(path, ttlMs = 600_000L).toOption.get
    assertEquals(m2.size, 0)
  }

  test("persistent mailroom: corrupt file → load returns Left") {
    val path = Files.createTempFile("siida-mr-corrupt-", ".simr")
    Files.write(path, Array.fill[Byte](20)(0xFF.toByte))
    val res = Mailroom.persistent(path, ttlMs = 60_000L)
    assert(res.isLeft, s"expected Left for corrupt file, got $res")
  }
