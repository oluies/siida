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

package siida.pkg

import java.security.SecureRandom
import munit.FunSuite
import siida.crypto.api.HybridOnion
import siida.pkg.api.{Friendship, FriendshipError}

/** Spec 020 US1 — AddResponse round-trip + edge cases. */
final class AddResponseSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  test("bob → alice: buildAddResponse → processAddResponse recovers (identity, ack)") {
    val (_, alicePk)   = HybridOnion.generateBundle(fixedRng("ar-alice"))
    val aliceSk        = HybridOnion.generateBundle(fixedRng("ar-alice"))._1
    val _              = alicePk
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("rp-alice"))
    val (_, _)     = HybridOnion.generateBundle(fixedRng("rp-bob"))

    val resp = Friendship.buildAddResponse(
      "bob".getBytes("UTF-8"),
      "ack ok".getBytes("UTF-8"),
      aPk,
      fixedRng("rp-build"),
    )
    val content = Friendship.processAddResponse(aSk, resp).toOption.get
    assertEquals(content.senderIdentity.toSeq, "bob".getBytes("UTF-8").toSeq)
    assertEquals(content.ackPayload.toSeq, "ack ok".getBytes("UTF-8").toSeq)
    val _ = aliceSk
  }

  test("processAddResponse: tampered ciphertext → DecryptionFailed") {
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("tamp-alice"))
    val resp = Friendship.buildAddResponse(
      "bob".getBytes("UTF-8"),
      "ack".getBytes("UTF-8"),
      aPk,
      fixedRng("tamp-build"),
    )
    val bytes = Friendship.serialiseAddResponse(resp)
    bytes(bytes.length - 1) = (bytes(bytes.length - 1) ^ 0x01).toByte
    val tampered = Friendship.deserialiseAddResponse(bytes).toOption.get
    val res = Friendship.processAddResponse(aSk, tampered)
    assertEquals(res, Left(FriendshipError.DecryptionFailed))
  }

  test("deserialiseAddResponse: unknown alg-ID → UnsupportedAlgorithm") {
    val (_, aPk) = HybridOnion.generateBundle(fixedRng("alg-alice"))
    val resp = Friendship.buildAddResponse(
      "bob".getBytes("UTF-8"),
      "ack".getBytes("UTF-8"),
      aPk,
      fixedRng("alg-build"),
    )
    val bytes = Friendship.serialiseAddResponse(resp)
    bytes(0) = 0x42.toByte
    val res = Friendship.deserialiseAddResponse(bytes)
    assertEquals(res, Left(FriendshipError.UnsupportedAlgorithm))
  }

  test("deserialiseAddResponse: too-short → InvalidLength") {
    val res = Friendship.deserialiseAddResponse(new Array[Byte](50))
    assertEquals(res, Left(FriendshipError.InvalidLength))
  }

  test("buildAddResponse with empty ack payload still round-trips") {
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("empty-alice"))
    val resp = Friendship.buildAddResponse(
      "bob".getBytes("UTF-8"),
      Array.emptyByteArray,
      aPk,
      fixedRng("empty-build"),
    )
    val content = Friendship.processAddResponse(aSk, resp).toOption.get
    assertEquals(content.ackPayload.length, 0)
  }
