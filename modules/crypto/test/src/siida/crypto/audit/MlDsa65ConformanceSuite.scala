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
import org.bouncycastle.pqc.crypto.crystals.dilithium.{
  DilithiumKeyGenerationParameters,
  DilithiumKeyPairGenerator,
  DilithiumParameters,
  DilithiumPrivateKeyParameters,
  DilithiumPublicKeyParameters,
  DilithiumSigner,
}

/** Spec 016 — ML-DSA-65 conformance against NIST FIPS 204.
 *
 *  Same baseline-snapshot pattern as [[MlKem768ConformanceSuite]].
 *  Audits BC's Dilithium3 keyGen and sigGen against the FIPS 204
 *  ACVP vectors and asserts the result matches the documented
 *  baseline for the currently-pinned BC version.
 *
 *  Particular gap for ML-DSA-65: BC 1.78.1's `DilithiumSigner` does
 *  NOT accept a `ctx` parameter. FIPS 204's ML-DSA.Sign(sk, M, ctx)
 *  prepends `0x00 0x00 || ctx || M` to the signing input even when
 *  `ctx` is empty. BC signs `M` directly. Even with `ctx = b""`,
 *  this difference alone causes every signature to mismatch.
 */
final class MlDsa65ConformanceSuite extends FunSuite:

  private val params = DilithiumParameters.dilithium3

  // BC 1.78.1 baseline: BC's Round-3 Dilithium does not match
  // FIPS 204 ML-DSA-65 for any vector.

  private val baselineKeyGenPass:  Int = 0
  private val baselineKeyGenTotal: Int = 25

  private val baselineSigGenPass:  Int = 0
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
      val gen = DilithiumKeyPairGenerator()
      gen.init(DilithiumKeyGenerationParameters(rng, params))
      val pair = gen.generateKeyPair()
      val sk = pair.getPrivate.asInstanceOf[DilithiumPrivateKeyParameters].getEncoded
      val pk = pair.getPublic.asInstanceOf[DilithiumPublicKeyParameters].getEncoded

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
    var ctxNonEmptyCount = 0
    val firstFailure = scala.collection.mutable.ListBuffer.empty[String]

    for tg <- tgs; t <- tg.tests do
      total += 1
      val tcId    = t.field("tcId").asLong.toInt
      val sk      = AcvpVectorReader.hex(t.field("sk").asString)
      val pk      = AcvpVectorReader.hex(t.field("pk").asString)
      val msg     = AcvpVectorReader.hex(t.field("message").asString)
      val context = AcvpVectorReader.hex(t.field("context").asString)
      val expectedSig = AcvpVectorReader.hex(t.field("signature").asString)

      if context.length > 0 then ctxNonEmptyCount += 1

      val pubKey = DilithiumPublicKeyParameters(params, pk)
      val priv   = DilithiumPrivateKeyParameters(params, sk, pubKey)
      val signer = DilithiumSigner()
      signer.init(true, priv)
      val sig =
        try signer.generateSignature(msg)
        catch case _: Throwable => Array.emptyByteArray

      if java.util.Arrays.equals(sig, expectedSig) then pass += 1
      else if firstFailure.size < 1 then
        firstFailure += s"tcId=$tcId  ctx_len=${context.length}  expected ${AcvpVectorReader.hexShort(expectedSig)} got=${AcvpVectorReader.hexShort(sig)}"

    assertEquals(total, baselineSigGenTotal, "vector-set size changed")
    assertEquals(pass, baselineSigGenPass,
      s"""ML-DSA-65 sigGen baseline DRIFT — observed $pass/$total, baseline $baselineSigGenPass/$baselineSigGenTotal.
         |Non-empty ctx in $ctxNonEmptyCount of $total cases — BC 1.78.1 ignores ctx.
         |${if firstFailure.nonEmpty then s"First diff: ${firstFailure.head}" else "All passed — BC now matches FIPS 204!"}
         |Action: update specs/016-audit-pq-conformance/notes-conformance.md and the baseline constants in this suite.""".stripMargin)
  }
