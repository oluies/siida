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

package siida.crypto.internal

import munit.FunSuite

/** Smallest possible check that the FFI loads and one trivial call
 *  works on the current architecture. NOT a cryptographic-correctness
 *  test — that lives in IBESuite / BLSSuite / BN254VectorsSuite
 *  (later user stories).
 */
final class NativeSmokeSuite extends FunSuite:

  test("siida_bn254_init returns 0 (library loads)") {
    val rc = Native.lib.siida_bn254_init()
    assertEquals(rc, 0)
  }

  test("siida_bn254_g1_generator populates a non-zero 32-byte buffer") {
    val g1 = Bn254Ops.g1Generator()
    assertEquals(g1.length, Native.G1_BYTES)
    assert(g1.exists(_ != 0.toByte), "G1 generator should not be all zeros")
  }

  test("siida_bn254_g2_generator populates a non-zero 64-byte buffer") {
    val g2 = Bn254Ops.g2Generator()
    assertEquals(g2.length, Native.G2_BYTES)
    assert(g2.exists(_ != 0.toByte), "G2 generator should not be all zeros")
  }

  test("subgroup check accepts the G1 generator") {
    val g1 = Bn254Ops.g1Generator()
    assertEquals(Bn254Ops.g1SubgroupCheck(g1), Right(()))
  }

  test("subgroup check accepts the G2 generator") {
    val g2 = Bn254Ops.g2Generator()
    assertEquals(Bn254Ops.g2SubgroupCheck(g2), Right(()))
  }

  test("subgroup check rejects garbage 32-byte buffer") {
    val garbage = Array.fill[Byte](Native.G1_BYTES)(0xff.toByte)
    val result = Bn254Ops.g1SubgroupCheck(garbage)
    assert(result.isLeft, s"expected Left, got $result")
  }
