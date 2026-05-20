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

package siida.crypto.api

import java.security.SecureRandom
import munit.FunSuite
import siida.crypto.internal.HybridOnionWire

/** Spec 012 US2 — wire-format algorithm-ID byte enforcement.
 *
 *  Four properties, each a single assertion:
 *    (1) An honest 0x01 envelope round-trips through unpack into the
 *        four field slices with matching bytes.
 *    (2) Flipping byte 0 to 0x00 (the deprecated classical NaCl-box
 *        algorithm) yields `Left(UnsupportedAlgorithm)`.
 *    (3) Flipping byte 0 to 0x42 (an unknown future algorithm) also
 *        yields `Left(UnsupportedAlgorithm)` — uniform refusal per
 *        FR-006.
 *    (4) Truncating the envelope below the 1137-byte fixed overhead
 *        yields `Left(InvalidLength)`.
 */
final class HybridOnionWireSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private val payload = "wire-suite".getBytes("UTF-8")

  private def honestEnvelope: Array[Byte] =
    val (_, public) = HybridOnion.generateBundle(fixedRng("wire/keys"))
    val layer = HybridOnion.encrypt(public, payload, fixedRng("wire/encrypt"))
    HybridOnion.serialiseLayer(layer)

  test("honest 0x01 envelope unpacks into matching field slices") {
    val bytes = honestEnvelope
    HybridOnionWire.unpack(bytes) match
      case Right((algId, ephPk, mlKemCt, aeadCtTag)) =>
        assertEquals(algId, HybridOnionWire.AlgHybridV1,
          "alg-ID byte mismatch")
        assertEquals(ephPk.length, HybridOnionWire.X25519PkBytes,
          "ephPk wrong length")
        assertEquals(mlKemCt.length, HybridOnionWire.MlKemCtBytes,
          "mlKemCt wrong length")
        assert(aeadCtTag.length >= HybridOnionWire.Poly1305TagBytes,
          s"aeadCtTag should be >= 16 bytes, got ${aeadCtTag.length}")
        // Field offsets are positional — verify the slices match the
        // raw envelope bytes at the documented offsets.
        val expectedEphPk = java.util.Arrays.copyOfRange(bytes, 1, 33)
        val expectedMlKemCt = java.util.Arrays.copyOfRange(bytes, 33, 1121)
        val expectedAeadCtTag = java.util.Arrays.copyOfRange(bytes, 1121, bytes.length)
        assertEquals(ephPk.toSeq, expectedEphPk.toSeq, "ephPk slice mismatch")
        assertEquals(mlKemCt.toSeq, expectedMlKemCt.toSeq, "mlKemCt slice mismatch")
        assertEquals(aeadCtTag.toSeq, expectedAeadCtTag.toSeq, "aeadCtTag slice mismatch")
      case Left(e) =>
        fail(s"honest envelope failed to unpack: $e")
  }

  test("alg-ID 0x00 (deprecated classical NaCl box) rejected with UnsupportedAlgorithm") {
    val tampered = honestEnvelope
    tampered(0) = HybridOnionWire.AlgDeprecatedClassical
    val res = HybridOnionWire.unpack(tampered)
    assertEquals(res.left.map(identity),
      Left[HybridOnionError, (Byte, Array[Byte], Array[Byte], Array[Byte])](HybridOnionError.UnsupportedAlgorithm))
  }

  test("alg-ID 0x42 (unknown future variant) rejected with UnsupportedAlgorithm") {
    val tampered = honestEnvelope
    tampered(0) = 0x42.toByte
    val res = HybridOnionWire.unpack(tampered)
    assertEquals(res.left.map(identity),
      Left[HybridOnionError, (Byte, Array[Byte], Array[Byte], Array[Byte])](HybridOnionError.UnsupportedAlgorithm))
  }

  test("truncated envelope (below 1137-byte fixed overhead) rejected with InvalidLength") {
    val truncated = new Array[Byte](HybridOnionWire.FixedOverheadBytes - 1)
    truncated(0) = HybridOnionWire.AlgHybridV1
    val res = HybridOnionWire.unpack(truncated)
    assertEquals(res.left.map(identity),
      Left[HybridOnionError, (Byte, Array[Byte], Array[Byte], Array[Byte])](HybridOnionError.InvalidLength))
  }
