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

final class BLSSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private val message = "siida config-chain epoch 42".getBytes("UTF-8")

  test("sign / verify: a fresh signature verifies under its matching public key") {
    val (sk, pk) = BLS.generateKeyPair(fixedRng("bls/sign"))
    val sig = BLS.sign(sk, message)
    assert(BLS.verify(pk, message, sig), "BLS.verify rejected an honest signature")
  }

  test("wrong key: verify returns false (no exception)") {
    val (sk1, _)   = BLS.generateKeyPair(fixedRng("bls/wrong-1"))
    val (_,   pk2) = BLS.generateKeyPair(fixedRng("bls/wrong-2"))
    val sig = BLS.sign(sk1, message)
    assert(!BLS.verify(pk2, message, sig), "BLS.verify accepted a signature under the wrong key")
  }

  test("tampered message: verify returns false") {
    val (sk, pk) = BLS.generateKeyPair(fixedRng("bls/tamper"))
    val sig = BLS.sign(sk, message)
    val tampered = message.clone()
    tampered(0) = (tampered(0) ^ 0x01).toByte
    assert(!BLS.verify(pk, tampered, sig), "BLS.verify accepted a signature on the wrong message")
  }

  test("proof-of-possession: roundtrip verifies under the signer's own key") {
    val (sk, pk) = BLS.generateKeyPair(fixedRng("bls/pop"))
    val pop = BLS.proofOfPossession(sk)
    assert(BLS.verifyPoP(pk, pop), "PoP didn't verify under the matching public key")
  }

  test("PoP doesn't cross-verify under a different public key") {
    val (sk1, _)   = BLS.generateKeyPair(fixedRng("bls/pop-cross-1"))
    val (_,   pk2) = BLS.generateKeyPair(fixedRng("bls/pop-cross-2"))
    val pop1 = BLS.proofOfPossession(sk1)
    assert(!BLS.verifyPoP(pk2, pop1),
      "PoP for one key verified under a different key; rogue-key resistance broken")
  }

  test("aggregate over same message: 3 signers + PoPs verify under the aggregate") {
    val (sk1, pk1) = BLS.generateKeyPair(fixedRng("bls/agg-1"))
    val (sk2, pk2) = BLS.generateKeyPair(fixedRng("bls/agg-2"))
    val (sk3, pk3) = BLS.generateKeyPair(fixedRng("bls/agg-3"))

    val sig1 = BLS.sign(sk1, message)
    val sig2 = BLS.sign(sk2, message)
    val sig3 = BLS.sign(sk3, message)

    val agg = BLS.aggregate(Seq(sig1, sig2, sig3)).toOption.getOrElse {
      fail("aggregate Returned Left for three valid signatures")
    }

    val pops = Seq(sk1, sk2, sk3).map(BLS.proofOfPossession)
    val pks  = Seq(pk1, pk2, pk3)

    assert(BLS.verifyAggregate(pks, pops, message, agg),
      "verifyAggregate rejected an honest 3-signer aggregate")
  }

  test("aggregate verify fails if any PoP is missing or wrong") {
    val (sk1, pk1) = BLS.generateKeyPair(fixedRng("bls/badpop-1"))
    val (sk2, pk2) = BLS.generateKeyPair(fixedRng("bls/badpop-2"))
    val (_,   pkX) = BLS.generateKeyPair(fixedRng("bls/badpop-X"))

    val agg = BLS.aggregate(Seq(BLS.sign(sk1, message), BLS.sign(sk2, message)))
      .toOption.getOrElse { fail("aggregate failed") }
    val realPops = Seq(BLS.proofOfPossession(sk1), BLS.proofOfPossession(sk2))

    // Same pks but one PoP swapped for an unrelated key's PoP -> should reject
    assert(
      !BLS.verifyAggregate(Seq(pk1, pkX), realPops, message, agg),
      "verifyAggregate accepted a rogue public key without a matching PoP"
    )
  }

  test("aggregate refuses empty list") {
    BLS.aggregate(Seq.empty) match
      case Left(BLSError.EmptyAggregation) => () // expected
      case other => fail(s"expected Left(EmptyAggregation), got $other")
  }

  test("serialise / deserialise round-trip for keys and signature") {
    val (sk, pk) = BLS.generateKeyPair(fixedRng("bls/ser"))
    val sig = BLS.sign(sk, message)
    val pop = BLS.proofOfPossession(sk)

    assertEquals(BLS.serialisePrivateKey(sk).toSeq,
      BLS.serialisePrivateKey(BLS.deserialisePrivateKey(BLS.serialisePrivateKey(sk)).toOption.get).toSeq)
    assertEquals(BLS.serialisePublicKey(pk).toSeq,
      BLS.serialisePublicKey(BLS.deserialisePublicKey(BLS.serialisePublicKey(pk)).toOption.get).toSeq)
    assertEquals(BLS.serialiseSignature(sig).toSeq,
      BLS.serialiseSignature(BLS.deserialiseSignature(BLS.serialiseSignature(sig)).toOption.get).toSeq)
    assertEquals(BLS.serialisePoP(pop).toSeq,
      BLS.serialisePoP(BLS.deserialisePoP(BLS.serialisePoP(pop)).toOption.get).toSeq)
  }

  test("verifyAggregateDistinct: 3 signers over 3 distinct messages verifies") {
    val (sk1, pk1) = BLS.generateKeyPair(fixedRng("bls/dist-1"))
    val (sk2, pk2) = BLS.generateKeyPair(fixedRng("bls/dist-2"))
    val (sk3, pk3) = BLS.generateKeyPair(fixedRng("bls/dist-3"))

    val m1 = "epoch 1 config".getBytes("UTF-8")
    val m2 = "epoch 2 config".getBytes("UTF-8")
    val m3 = "epoch 3 config".getBytes("UTF-8")

    val agg = BLS.aggregate(Seq(
      BLS.sign(sk1, m1),
      BLS.sign(sk2, m2),
      BLS.sign(sk3, m3),
    )).toOption.getOrElse { fail("aggregate failed") }

    assert(
      BLS.verifyAggregateDistinct(Seq((pk1, m1), (pk2, m2), (pk3, m3)), agg),
      "verifyAggregateDistinct rejected an honest 3-signer distinct-message aggregate"
    )
  }

  test("verifyAggregateDistinct rejects mismatched (pk, msg) order") {
    val (sk1, pk1) = BLS.generateKeyPair(fixedRng("bls/dist-mix-1"))
    val (sk2, pk2) = BLS.generateKeyPair(fixedRng("bls/dist-mix-2"))

    val m1 = "alice's message".getBytes("UTF-8")
    val m2 = "bob's message".getBytes("UTF-8")

    val agg = BLS.aggregate(Seq(BLS.sign(sk1, m1), BLS.sign(sk2, m2)))
      .toOption.getOrElse { fail("aggregate failed") }

    // Swap m1 and m2 in the verification input → pairing check should fail
    assert(
      !BLS.verifyAggregateDistinct(Seq((pk1, m2), (pk2, m1)), agg),
      "verifyAggregateDistinct accepted swapped (pk, msg) pairs"
    )
  }

  test("verifyAggregateDistinct rejects duplicate messages (caller should use verifyAggregate instead)") {
    val (sk1, pk1) = BLS.generateKeyPair(fixedRng("bls/dist-dup-1"))
    val (sk2, pk2) = BLS.generateKeyPair(fixedRng("bls/dist-dup-2"))
    val sameMsg = "shared".getBytes("UTF-8")
    val agg = BLS.aggregate(Seq(BLS.sign(sk1, sameMsg), BLS.sign(sk2, sameMsg)))
      .toOption.getOrElse { fail("aggregate failed") }
    assert(
      !BLS.verifyAggregateDistinct(Seq((pk1, sameMsg), (pk2, sameMsg)), agg),
      "verifyAggregateDistinct accepted duplicate messages; should be verifyAggregate's job"
    )
  }

  test("verifyAggregateDistinct rejects empty input") {
    val (sk, _) = BLS.generateKeyPair(fixedRng("bls/dist-empty"))
    val agg = BLS.aggregate(Seq(BLS.sign(sk, message))).toOption.get
    assert(!BLS.verifyAggregateDistinct(Seq.empty, agg))
  }
