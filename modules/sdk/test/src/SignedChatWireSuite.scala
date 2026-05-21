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
import siida.sdk.api.{SdkError, SdkEnvelope, SignedChatWire}

final class SignedChatWireSuite extends FunSuite:

  test("encode/decode roundtrip") {
    val id      = "alice".getBytes("UTF-8")
    val sig     = Array.fill[Byte](3310)(0x42.toByte)
    val payload = "hello bob".getBytes("UTF-8")
    val wire    = SignedChatWire.encode(id, sig, payload)
    SignedChatWire.decode(wire) match
      case Right((id2, sig2, payload2)) =>
        assert(java.util.Arrays.equals(id, id2))
        assert(java.util.Arrays.equals(sig, sig2))
        assert(java.util.Arrays.equals(payload, payload2))
      case Left(e) => fail(s"decode failed: $e")
  }

  test("signedMessage binds SDK type byte, sender, recipient, payload") {
    val a = "alice".getBytes("UTF-8")
    val b = "bob".getBytes("UTF-8")
    val p = "hi".getBytes("UTF-8")
    val msg = SignedChatWire.signedMessage(a, b, p)
    // first byte == 0x04 (SignedChat type)
    assertEquals(msg(0), SdkEnvelope.Type.SignedChat)
    // changing recipient must change the signed bytes
    val c = "charlie".getBytes("UTF-8")
    val msg2 = SignedChatWire.signedMessage(a, c, p)
    assert(!java.util.Arrays.equals(msg, msg2),
      "signed message must differ when recipient differs")
  }

  test("decode rejects short input under length prefix") {
    SignedChatWire.decode(Array[Byte](0x00)) match
      case Left(SdkError.MalformedEnvelope(_)) => ()
      case other => fail(s"expected MalformedEnvelope, got $other")
  }

  test("decode rejects empty sender identity") {
    val wire = Array[Byte](0x00, 0x00, 0x00, 0x00) // id_len=0
    SignedChatWire.decode(wire) match
      case Left(SdkError.MalformedEnvelope(_)) => ()
      case other => fail(s"expected MalformedEnvelope, got $other")
  }

  test("decode rejects sender_id_len > input") {
    val wire = Array[Byte](0xFF.toByte, 0xFF.toByte, 0x00, 0x00)
    SignedChatWire.decode(wire) match
      case Left(SdkError.MalformedEnvelope(_)) => ()
      case other => fail(s"expected MalformedEnvelope, got $other")
  }

  test("decode rejects sig_len > remaining") {
    // id_len=1 "a"; then sig_len declared as 9999 but only 0 bytes follow
    val wire = Array[Byte](
      0x00, 0x01, 'a'.toByte,
      0xFF.toByte, 0xFF.toByte,
    )
    SignedChatWire.decode(wire) match
      case Left(SdkError.MalformedEnvelope(_)) => ()
      case other => fail(s"expected MalformedEnvelope, got $other")
  }
