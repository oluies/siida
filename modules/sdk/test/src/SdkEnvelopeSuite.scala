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

package siida.sdk

import munit.FunSuite
import siida.sdk.api.{SdkEnvelope, SdkError}

final class SdkEnvelopeSuite extends FunSuite:

  test("wrap → parse round-trips chat type") {
    val payload = "hello".getBytes("UTF-8")
    val wrapped = SdkEnvelope.wrap(SdkEnvelope.Type.ChatMessage, payload)
    val (typ, inner) = SdkEnvelope.parse(wrapped).toOption.get
    assertEquals(typ, SdkEnvelope.Type.ChatMessage)
    assertEquals(inner.toSeq, payload.toSeq)
  }

  test("wrap → parse round-trips add-request type") {
    val payload = Array.fill[Byte](20)(0x55.toByte)
    val wrapped = SdkEnvelope.wrap(SdkEnvelope.Type.AddRequest, payload)
    val (typ, inner) = SdkEnvelope.parse(wrapped).toOption.get
    assertEquals(typ, SdkEnvelope.Type.AddRequest)
    assertEquals(inner.toSeq, payload.toSeq)
  }

  test("parse rejects empty input") {
    val res = SdkEnvelope.parse(Array.emptyByteArray)
    assert(res.isLeft, s"expected Left, got $res")
    res match
      case Left(SdkError.MalformedEnvelope(_)) => ()
      case other => fail(s"expected MalformedEnvelope, got $other")
  }

  test("wrap preserves length (1 + payload)") {
    val pad = Array.fill[Byte](100)(0x11.toByte)
    val wrapped = SdkEnvelope.wrap(SdkEnvelope.Type.ChatMessage, pad)
    assertEquals(wrapped.length, 101)
  }
