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

import munit.FunSuite
import siida.crypto.internal.Combiner

/** Spec 012 US3 — SHA3-256 hybrid combiner KAT.
 *
 *  Locks the combiner construction by asserting one fixed input/output
 *  pair. Any change to the combiner (different DST string, different
 *  hash function, different field-concatenation order) breaks this
 *  test and forces an explicit spec amendment.
 *
 *  Inputs (documented for reproducibility by any SHA3-256
 *  implementation):
 *    - classical_ss : 32 bytes, all 0x01
 *    - ml_kem_ss    : 32 bytes, all 0x02
 *    - dst          : "siida/hybrid/v1/onion-layer" (US-ASCII, 27 bytes)
 *
 *  Expected output regenerated via, e.g.:
 *
 *      python3 -c "import hashlib; h=hashlib.sha3_256();
 *        h.update(bytes([1]*32)); h.update(bytes([2]*32));
 *        h.update(b'siida/hybrid/v1/onion-layer'); print(h.hexdigest())"
 */
final class HybridCombinerSuite extends FunSuite:

  private def hex(bytes: Array[Byte]): String =
    val sb = new StringBuilder(bytes.length * 2)
    bytes.foreach: b =>
      sb.append("%02x".format(b & 0xff))
    sb.toString

  test("Combiner.combine matches the committed SHA3-256 KAT") {
    val classicalSs = Array.fill[Byte](32)(0x01)
    val mlKemSs     = Array.fill[Byte](32)(0x02)
    val out = Combiner.combine(classicalSs, mlKemSs, Combiner.OnionLayerDST)

    val expected = "0514367616ead248f8335d4f76447a8e9e0233721774d5f430cc43cfc251cb2b"
    assertEquals(hex(out), expected,
      "Combiner.combine output does not match the committed KAT — " +
      "the hybrid combiner construction has changed (DST? hash? order?).")
  }

  test("DST is the documented ASCII string") {
    val dst = new String(Combiner.OnionLayerDST, "US-ASCII")
    assertEquals(dst, "siida/hybrid/v1/onion-layer")
    assertEquals(Combiner.OnionLayerDST.length, 27,
      "OnionLayerDST length changed — KAT would need regeneration.")
  }
