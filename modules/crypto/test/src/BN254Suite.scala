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

/** Smoke tests for the public BN254 primitives (US3). Validates the
 *  API surface is wired correctly to the internal Bn254Ops; deeper
 *  KAT vectors are deferred to a follow-up PR.
 */
final class BN254Suite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  test("generators are non-zero and round-trip through serialise/deserialise") {
    val g1 = BN254.G1Generator
    val g2 = BN254.G2Generator
    val g1b = BN254.serialiseG1(g1)
    val g2b = BN254.serialiseG2(g2)
    assert(g1b.exists(_ != 0.toByte), "G1Generator serialised to all zeros")
    assert(g2b.exists(_ != 0.toByte), "G2Generator serialised to all zeros")

    val g1back = BN254.deserialiseG1(g1b).toOption.get
    val g2back = BN254.deserialiseG2(g2b).toOption.get
    assertEquals(BN254.serialiseG1(g1back).toSeq, g1b.toSeq)
    assertEquals(BN254.serialiseG2(g2back).toSeq, g2b.toSeq)
  }

  test("bilinearity: e(s·g1, g2) == e(g1, s·g2)") {
    val s = BN254.scalarRandom(fixedRng("bn254/bilinearity"))
    val sg1 = BN254.g1ScalarMul(s, BN254.G1Generator)
    val sg2 = BN254.g2ScalarMul(s, BN254.G2Generator)
    val left  = BN254.pairing(sg1, BN254.G2Generator)
    val right = BN254.pairing(BN254.G1Generator, sg2)
    assertEquals(BN254.serialiseG1.asInstanceOf[Array[Byte] => Array[Byte]](left.asInstanceOf[Array[Byte]]).length, 384,
      "GT element must serialise to 384 bytes")
    // Compare GT byte buffers directly.
    assertEquals(
      left.asInstanceOf[Array[Byte]].toSeq,
      right.asInstanceOf[Array[Byte]].toSeq,
      "bilinearity check failed: e(s·g1, g2) ≠ e(g1, s·g2)",
    )
  }

  test("g1Add is commutative") {
    val s1 = BN254.scalarRandom(fixedRng("bn254/add-1"))
    val s2 = BN254.scalarRandom(fixedRng("bn254/add-2"))
    val a = BN254.g1ScalarMul(s1, BN254.G1Generator)
    val b = BN254.g1ScalarMul(s2, BN254.G1Generator)
    val ab = BN254.g1Add(a, b)
    val ba = BN254.g1Add(b, a)
    assertEquals(BN254.serialiseG1(ab).toSeq, BN254.serialiseG1(ba).toSeq,
      "g1Add(a, b) ≠ g1Add(b, a)")
  }

  test("hashToG2 produces a valid G2 element (subgroup check passes)") {
    val dst = "SIIDA-BN254-G2-SSWU-RO-TEST".getBytes("US-ASCII")
    val pt = BN254.hashToG2("hello".getBytes("UTF-8"), dst)
    // Round-trip through deserialiseG2 — fails if subgroup check rejects.
    val b = BN254.serialiseG2(pt)
    val back = BN254.deserialiseG2(b)
    assert(back.isRight, s"hashToG2 produced a point that failed subgroup check: $back")
  }

  test("deserialiseG1 rejects wrong-length input") {
    val res = BN254.deserialiseG1(new Array[Byte](10))
    assertEquals(res, Left(BN254Error.InvalidLength))
  }

  test("deserialiseG2 rejects wrong-length input") {
    val res = BN254.deserialiseG2(new Array[Byte](10))
    assertEquals(res, Left(BN254Error.InvalidLength))
  }

  test("pairingCheck on empty input returns false") {
    assert(!BN254.pairingCheck(Seq.empty), "pairingCheck(empty) should not vacuously succeed")
  }

  test("scalarFromBytes reduces input mod r (large input doesn't throw)") {
    val maxBytes = Array.fill[Byte](32)(0xff.toByte)
    val s = BN254.scalarFromBytes(maxBytes)
    val out = BN254.scalarToBytes(s)
    assertEquals(out.length, 32)
    // After reduction the value should differ from input (since 0xff*32 > r)
    assert(!out.toSeq.equals(maxBytes.toSeq),
      "scalarFromBytes(0xff*32) should reduce; instead returned input unchanged")
  }
