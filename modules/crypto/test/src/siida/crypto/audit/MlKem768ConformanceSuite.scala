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

package siida.crypto.audit

import munit.FunSuite
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator
import org.bouncycastle.crypto.kems.{MLKEMExtractor, MLKEMGenerator}
import org.bouncycastle.crypto.params.{
  MLKEMKeyGenerationParameters,
  MLKEMParameters,
  MLKEMPrivateKeyParameters,
  MLKEMPublicKeyParameters,
}

/** Spec 016 — ML-KEM-768 conformance against NIST FIPS 203.
 *
 *  Runs every NIST ACVP test vector under `test/resources/acvp/` for
 *  ML-KEM-768 through Bouncy Castle and compares byte-for-byte.
 *  Records the pass/fail counts; asserts they match the documented
 *  **baseline** for the currently-pinned BC version.
 *
 *  Why a baseline rather than "all-must-pass":
 *    - The spec (016, FR-004) requires the audit to be part of
 *      `make test`. A hard "all-must-pass" assertion would break the
 *      build until the BC remediation lands, blocking all other
 *      work on main.
 *    - The current pin (BC 1.78.1, April 2024) predates FIPS 203
 *      finalisation (August 2024); a 0/25 baseline is the expected
 *      and documented state.
 *    - A future BC bump that improves conformance will FLIP the
 *      result (e.g. 0/25 → 25/25), which causes this test to fail
 *      and forces an explicit baseline update via
 *      `notes-conformance.md` — exactly the regression-protection
 *      contract.
 *
 *  When BC is bumped (e.g., to a version that ships FIPS 203
 *  finalisation), this test WILL fail with a clear message; the
 *  fix is to update the `expected*` constants below and the
 *  `notes-conformance.md` report.
 */
final class MlKem768ConformanceSuite extends FunSuite:

  private val params = MLKEMParameters.ml_kem_768

  // ---- Documented baseline for the currently-pinned BC version ----
  // BC 1.84 (May 2026, post-FIPS-203-finalisation). Initial
  // optimistic baseline: assume the FIPS-named MLKEM* classes are
  // fully conformant. If they're not, the audit will fail loudly
  // and the human reading the failure updates these constants.

  private val baselineKeyGenPass:   Int = 25
  private val baselineKeyGenTotal:  Int = 25

  private val baselineEncapPass:   Int = 25
  private val baselineEncapTotal:  Int = 25

  private val baselineDecapPass:   Int = 25
  private val baselineDecapTotal:  Int = 25

  // ----------------------------------------------------------------

  test("ML-KEM-768 keyGen — BC byte-for-byte matches against FIPS 203 ACVP (baseline check)") {
    val vf = AcvpVectorReader.load("/acvp/ml-kem-768-keygen.json")
    val tgs = vf.testGroups.filter(_.parameterSet == "ML-KEM-768")
    assert(tgs.nonEmpty, "no ML-KEM-768 test groups found")

    var pass = 0
    var total = 0
    val firstFailure = scala.collection.mutable.ListBuffer.empty[String]

    for tg <- tgs; t <- tg.tests do
      total += 1
      val tcId = t.field("tcId").asLong.toInt
      val d    = AcvpVectorReader.hex(t.field("d").asString)
      val z    = AcvpVectorReader.hex(t.field("z").asString)
      val expectedEk = AcvpVectorReader.hex(t.field("ek").asString)
      val expectedDk = AcvpVectorReader.hex(t.field("dk").asString)

      val rng = DeterministicSecureRandom(d ++ z)
      val gen = MLKEMKeyPairGenerator()
      gen.init(MLKEMKeyGenerationParameters(rng, params))
      val pair = gen.generateKeyPair()
      val sk   = pair.getPrivate.asInstanceOf[MLKEMPrivateKeyParameters].getEncoded
      val pk   = pair.getPublic.asInstanceOf[MLKEMPublicKeyParameters].getEncoded

      if java.util.Arrays.equals(pk, expectedEk) && java.util.Arrays.equals(sk, expectedDk) then
        pass += 1
      else if firstFailure.size < 1 then
        firstFailure += s"tcId=$tcId  expected ek=${AcvpVectorReader.hexShort(expectedEk)} got=${AcvpVectorReader.hexShort(pk)}"

    assertEquals(total, baselineKeyGenTotal,
      s"vector-set size changed — vectors file replaced?")
    assertEquals(pass, baselineKeyGenPass,
      s"""ML-KEM-768 keyGen baseline DRIFT — observed $pass/$total passed, baseline says $baselineKeyGenPass/$baselineKeyGenTotal.
         |${if firstFailure.nonEmpty then s"First diff: ${firstFailure.head}" else "All passed — BC now conforms to FIPS 203!"}
         |Action: update specs/016-audit-pq-conformance/notes-conformance.md and the baseline constants in this suite.""".stripMargin)
  }

  test("ML-KEM-768 encap — BC byte-for-byte matches against FIPS 203 ACVP (baseline check)") {
    val vf = AcvpVectorReader.load("/acvp/ml-kem-768-encapdecap.json")
    val tgs = vf.testGroups.filter(t => t.parameterSet == "ML-KEM-768" && t.testType == "AFT")
    assert(tgs.nonEmpty, "no ML-KEM-768 AFT encap test groups found")

    var pass = 0
    var total = 0
    val firstFailure = scala.collection.mutable.ListBuffer.empty[String]

    for tg <- tgs; t <- tg.tests do
      total += 1
      val tcId = t.field("tcId").asLong.toInt
      val ek   = AcvpVectorReader.hex(t.field("ek").asString)
      val m    = AcvpVectorReader.hex(t.field("m").asString)
      val expectedC = AcvpVectorReader.hex(t.field("c").asString)
      val expectedK = AcvpVectorReader.hex(t.field("k").asString)

      val rng = DeterministicSecureRandom(m)
      val pk  = MLKEMPublicKeyParameters(params, ek)
      val enc = MLKEMGenerator(rng)
      val sec = enc.generateEncapsulated(pk)
      val c   = sec.getEncapsulation
      val k   = sec.getSecret

      if java.util.Arrays.equals(c, expectedC) && java.util.Arrays.equals(k, expectedK) then
        pass += 1
      else if firstFailure.size < 1 then
        firstFailure += s"tcId=$tcId  expected c=${AcvpVectorReader.hexShort(expectedC)} got=${AcvpVectorReader.hexShort(c)}"

    assertEquals(total, baselineEncapTotal, "vector-set size changed")
    assertEquals(pass, baselineEncapPass,
      s"""ML-KEM-768 encap baseline DRIFT — observed $pass/$total passed, baseline says $baselineEncapPass/$baselineEncapTotal.
         |${if firstFailure.nonEmpty then s"First diff: ${firstFailure.head}" else "All passed — BC now conforms to FIPS 203!"}
         |Action: update specs/016-audit-pq-conformance/notes-conformance.md and the baseline constants in this suite.""".stripMargin)
  }

  test("ML-KEM-768 decap — BC byte-for-byte matches against FIPS 203 ACVP (baseline check)") {
    val vf = AcvpVectorReader.load("/acvp/ml-kem-768-encapdecap.json")
    val tgs = vf.testGroups.filter(t => t.parameterSet == "ML-KEM-768" && t.testType == "AFT")
    assert(tgs.nonEmpty, "no ML-KEM-768 AFT decap test groups found")

    var pass = 0
    var total = 0

    for tg <- tgs; t <- tg.tests do
      total += 1
      val dk   = AcvpVectorReader.hex(t.field("dk").asString)
      val c    = AcvpVectorReader.hex(t.field("c").asString)
      val expectedK = AcvpVectorReader.hex(t.field("k").asString)

      val sk = MLKEMPrivateKeyParameters(params, dk)
      val ext = MLKEMExtractor(sk)
      val k  =
        try ext.extractSecret(c)
        catch case _: Throwable => Array.emptyByteArray

      if java.util.Arrays.equals(k, expectedK) then pass += 1

    assertEquals(total, baselineDecapTotal, "vector-set size changed")
    assertEquals(pass, baselineDecapPass,
      s"""ML-KEM-768 decap baseline DRIFT — observed $pass/$total passed, baseline $baselineDecapPass/$baselineDecapTotal.
         |Action: update notes-conformance.md and baselines.""".stripMargin)
  }
