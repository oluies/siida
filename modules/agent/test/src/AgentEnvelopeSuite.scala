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

package siida.agent

import munit.FunSuite
import siida.agent.api.AgentEnvelope

final class AgentEnvelopeSuite extends FunSuite:

  test("encode → decode round-trips Request") {
    val rid = Array.fill[Byte](16)(0x42.toByte)
    val payload = "hello".getBytes("UTF-8")
    val bytes = AgentEnvelope.encode(AgentEnvelope.Kind.Request, rid, payload)
    val d = AgentEnvelope.decode(bytes).get
    assertEquals(d.kind, AgentEnvelope.Kind.Request)
    assertEquals(d.requestId.toSeq, rid.toSeq)
    assertEquals(d.content.toSeq, payload.toSeq)
  }

  test("encode → decode round-trips Notification with zero request id") {
    val payload = Array.fill[Byte](100)(0x11.toByte)
    val bytes = AgentEnvelope.encode(
      AgentEnvelope.Kind.Notification,
      AgentEnvelope.ZeroRequestId,
      payload,
    )
    val d = AgentEnvelope.decode(bytes).get
    assertEquals(d.kind, AgentEnvelope.Kind.Notification)
    assertEquals(d.requestId.toSeq, AgentEnvelope.ZeroRequestId.toSeq)
    assertEquals(d.content.toSeq, payload.toSeq)
  }

  test("decode returns None on wrong magic prefix") {
    val bytes = Array.fill[Byte](30)(0xAA.toByte)
    assertEquals(AgentEnvelope.decode(bytes), None)
  }

  test("decode returns None on truncated input") {
    val tiny = Array.fill[Byte](10)(0x53.toByte)
    assertEquals(AgentEnvelope.decode(tiny), None)
  }

  test("decode returns None on inconsistent content length") {
    val rid = new Array[Byte](16)
    val payload = "x".getBytes("UTF-8")
    val bytes = AgentEnvelope.encode(AgentEnvelope.Kind.Request, rid, payload)
    // Truncate by 1 byte → length doesn't match
    val truncated = java.util.Arrays.copyOf(bytes, bytes.length - 1)
    assertEquals(AgentEnvelope.decode(truncated), None)
  }

  test("empty content roundtrips") {
    val rid = new Array[Byte](16)
    val bytes = AgentEnvelope.encode(AgentEnvelope.Kind.Notification, rid, Array.emptyByteArray)
    val d = AgentEnvelope.decode(bytes).get
    assertEquals(d.content.length, 0)
  }
