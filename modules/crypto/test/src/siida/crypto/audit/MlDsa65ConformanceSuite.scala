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
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.params.{
  MLDSAKeyGenerationParameters,
  MLDSAParameters,
  MLDSAPrivateKeyParameters,
  MLDSAPublicKeyParameters,
  ParametersWithContext,
}
import org.bouncycastle.crypto.signers.MLDSASigner

/** Spec 016 — ML-DSA-65 conformance against NIST FIPS 204.
 *
 *  Same baseline-snapshot pattern as [[MlKem768ConformanceSuite]].
 *  Audits BC's ML-DSA-65 keyGen and sigGen against the FIPS 204
 *  ACVP vectors and asserts the result matches the documented
 *  baseline for the currently-pinned BC version.
 *
 *  Spec 017 (BC 1.78.1 → 1.84) introduced the FIPS-named `MLDSA*`
 *  classes plus `ParametersWithContext` to convey the FIPS 204
 *  `ctx` parameter through `MLDSASigner.init`.
 */
final class MlDsa65ConformanceSuite extends FunSuite:

  private val params = MLDSAParameters.ml_dsa_65

  // BC 1.84 baseline — empirical, to be re-verified by 017's
  // implementation step. Initial baselines mirror the pre-bump
  // state so the audit suite fails LOUDLY on the first run after
  // the BC bump; the human reading the failure updates these
  // constants to the new observed counts.

  private val baselineKeyGenPass:  Int = 25
  private val baselineKeyGenTotal: Int = 25

  private val baselineSigGenPass:  Int = 15
  private val baselineSigGenTotal: Int = 15

  test("ML-DSA-65 keyGen — BC byte-for-byte matches against FIPS 204 ACVP (baseline check)") {
    val vf = AcvpVectorReader.load("/acvp/ml-dsa-65-keygen.json")
    val tgs = vf.testGroups.filter(_.parameterSet == "ML-DSA-65")
    assert(tgs.nonEmpty, "no ML-DSA-65 test groups found")

    var pass = 0
    var total = 0
    val firstFailure = scala.collection.mutable.ListBuffer.empty[String]

    for tg <- tgs; t <- tg.tests do
      total += 1
      val tcId = t.field("tcId").asLong.toInt
      val seed = AcvpVectorReader.hex(t.field("seed").asString)
      val expectedPk = AcvpVectorReader.hex(t.field("pk").asString)
      val expectedSk = AcvpVectorReader.hex(t.field("sk").asString)

      val rng = DeterministicSecureRandom(seed)
      val gen = MLDSAKeyPairGenerator()
      gen.init(MLDSAKeyGenerationParameters(rng, params))
      val pair = gen.generateKeyPair()
      val sk = pair.getPrivate.asInstanceOf[MLDSAPrivateKeyParameters].getEncoded
      val pk = pair.getPublic.asInstanceOf[MLDSAPublicKeyParameters].getEncoded

      if java.util.Arrays.equals(pk, expectedPk) && java.util.Arrays.equals(sk, expectedSk) then
        pass += 1
      else if firstFailure.size < 1 then
        firstFailure += s"tcId=$tcId  expected pk=${AcvpVectorReader.hexShort(expectedPk)} got=${AcvpVectorReader.hexShort(pk)}"

    assertEquals(total, baselineKeyGenTotal, "vector-set size changed")
    assertEquals(pass, baselineKeyGenPass,
      s"""ML-DSA-65 keyGen baseline DRIFT — observed $pass/$total, baseline $baselineKeyGenPass/$baselineKeyGenTotal.
         |${if firstFailure.nonEmpty then s"First diff: ${firstFailure.head}" else "All passed — BC now conforms to FIPS 204!"}
         |Action: update specs/016-audit-pq-conformance/notes-conformance.md and the baseline constants in this suite.""".stripMargin)
  }

  test("ML-DSA-65 sigGen — BC byte-for-byte matches against FIPS 204 ACVP tg 3 (baseline check)") {
    val vf = AcvpVectorReader.load("/acvp/ml-dsa-65-siggen.json")
    val tgs = vf.testGroups.filter(t => t.parameterSet == "ML-DSA-65" && t.tgId == 3)
    assert(tgs.nonEmpty, "no ML-DSA-65 sigGen tg 3 found")

    var pass = 0
    var total = 0
    val firstFailure = scala.collection.mutable.ListBuffer.empty[String]

    for tg <- tgs; t <- tg.tests do
      total += 1
      val tcId    = t.field("tcId").asLong.toInt
      val sk      = AcvpVectorReader.hex(t.field("sk").asString)
      val msg     = AcvpVectorReader.hex(t.field("message").asString)
      val context = AcvpVectorReader.hex(t.field("context").asString)
      val expectedSig = AcvpVectorReader.hex(t.field("signature").asString)

      // tg 3 is "deterministic = true, signatureInterface = external,
      // preHash = pure, externalMu = false" — i.e., FIPS 204
      // ML-DSA.Sign_internal with rnd = 0^32 (deterministic), the
      // ctx parameter conveyed via ParametersWithContext, and the
      // raw message fed to the signer.
      val priv   = MLDSAPrivateKeyParameters(params, sk)
      val signer = MLDSASigner()
      signer.init(true, ParametersWithContext(priv, context))
      signer.update(msg, 0, msg.length)
      val sig =
        try signer.generateSignature()
        catch case _: Throwable => Array.emptyByteArray

      if java.util.Arrays.equals(sig, expectedSig) then pass += 1
      else if firstFailure.size < 1 then
        firstFailure += s"tcId=$tcId  ctx_len=${context.length}  expected ${AcvpVectorReader.hexShort(expectedSig)} got=${AcvpVectorReader.hexShort(sig)}"

    assertEquals(total, baselineSigGenTotal, "vector-set size changed")
    assertEquals(pass, baselineSigGenPass,
      s"""ML-DSA-65 sigGen baseline DRIFT — observed $pass/$total, baseline $baselineSigGenPass/$baselineSigGenTotal.
         |${if firstFailure.nonEmpty then s"First diff: ${firstFailure.head}" else "All passed — BC now matches FIPS 204!"}
         |Action: update specs/016-audit-pq-conformance/notes-conformance.md and the baseline constants in this suite.""".stripMargin)
  }
