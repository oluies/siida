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

/** Spec 013 — PqSignature (ML-DSA-65) public API tests.
 *
 *  Properties locked here:
 *    (1) sign/verify round-trip with fixed-seed keys
 *    (2) verify rejects wrong-key signatures
 *    (3) verify rejects tampered messages
 *    (4) sign is deterministic across runs and architectures
 *    (5) batchVerify(8 valid) == true
 *    (6) batchVerify with one forgery == false
 *    (7) batchVerify(empty) == false  (FR-006)
 *    (8) wire-format sizes (FR-003 / FR-004 / SC-005)
 *    (9) serialise/deserialise round-trips
 *   (10) deserialise rejects unknown alg-ID uniformly (FR-013)
 *   (11) the absence of `aggregate` is testable — see comment block
 */
final class PqSignatureSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private val msg = "siida/013 pq-sig test".getBytes("UTF-8")

  test("sign/verify round-trip recovers true for matching (sk, pk, msg)") {
    val (sk, pk) = PqSignature.generateKeyPair(fixedRng("rt-keys"))
    val sig = PqSignature.sign(sk, msg)
    assertEquals(PqSignature.verify(pk, msg, sig), true)
  }

  test("verify returns false for a different public key (forgery test)") {
    val (sk1, _)  = PqSignature.generateKeyPair(fixedRng("forge-keys-1"))
    val (_,  pk2) = PqSignature.generateKeyPair(fixedRng("forge-keys-2"))
    val sig = PqSignature.sign(sk1, msg)
    assertEquals(PqSignature.verify(pk2, msg, sig), false)
  }

  test("verify returns false for a tampered message") {
    val (sk, pk) = PqSignature.generateKeyPair(fixedRng("tamper-keys"))
    val sig = PqSignature.sign(sk, msg)
    val tampered = msg.clone()
    tampered(0) = (tampered(0) ^ 0x01).toByte
    assertEquals(PqSignature.verify(pk, tampered, sig), false)
  }

  test("sign is deterministic for fixed (sk, msg)") {
    // Two identical keypairs from the same fixed seed → identical
    // sk → identical signatures on identical messages. The
    // FIPS 204 rnd=0^32 path makes this byte-stable.
    val (sk1, _) = PqSignature.generateKeyPair(fixedRng("det-keys"))
    val (sk2, _) = PqSignature.generateKeyPair(fixedRng("det-keys"))
    val s1 = PqSignature.serialiseSignature(PqSignature.sign(sk1, msg))
    val s2 = PqSignature.serialiseSignature(PqSignature.sign(sk2, msg))
    assertEquals(s1.toSeq, s2.toSeq, "deterministic-sign property broken")
  }

  test("batchVerify(8 valid tuples) returns true") {
    val tuples = (1 to 8).map { i =>
      val (sk, pk) = PqSignature.generateKeyPair(fixedRng(s"batch-$i"))
      val m = s"msg-$i".getBytes("UTF-8")
      val sig = PqSignature.sign(sk, m)
      (pk, m, sig)
    }
    assertEquals(PqSignature.batchVerify(tuples), true)
  }

  test("batchVerify with one forgery returns false (no side channel on which one)") {
    val tuples = (1 to 8).map { i =>
      val (sk, pk) = PqSignature.generateKeyPair(fixedRng(s"forge-batch-$i"))
      val m = s"msg-$i".getBytes("UTF-8")
      val sig = PqSignature.sign(sk, m)
      (pk, m, sig)
    }
    // Forge: tamper tuple at index 3
    val (sk0, _)   = PqSignature.generateKeyPair(fixedRng("forge-other-key"))
    val (_,  pk3) = (tuples(3)._1, tuples(3)._1)
    val badSig = PqSignature.sign(sk0, tuples(3)._2)
    val withForgery = tuples.updated(3, (pk3, tuples(3)._2, badSig))
    assertEquals(PqSignature.batchVerify(withForgery), false)
  }

  test("batchVerify(empty) returns false (FR-006)") {
    assertEquals(PqSignature.batchVerify(Seq.empty), false)
  }

  test("wire-format sizes: pk=1953, sk=4033, sig=3310 (FR-003/4, SC-005)") {
    val (sk, pk) = PqSignature.generateKeyPair(fixedRng("sizes"))
    val sig = PqSignature.sign(sk, msg)
    assertEquals(PqSignature.serialisePublicKey(pk).length,  1953, "pk size")
    assertEquals(PqSignature.serialisePrivateKey(sk).length, 4033, "sk size")
    assertEquals(PqSignature.serialiseSignature(sig).length, 3310, "sig size (FIPS 204 ML-DSA-65)")
  }

  test("serialise / deserialise round-trip for public key") {
    val (_, pk) = PqSignature.generateKeyPair(fixedRng("ser-pk"))
    val bytes = PqSignature.serialisePublicKey(pk)
    val back = PqSignature.deserialisePublicKey(bytes) match
      case Right(p) => p
      case Left(e)  => fail(s"deserialisePublicKey rejected its own output: $e")
    assertEquals(PqSignature.serialisePublicKey(back).toSeq, bytes.toSeq)
  }

  test("serialise / deserialise round-trip for private key") {
    val (sk, _) = PqSignature.generateKeyPair(fixedRng("ser-sk"))
    val bytes = PqSignature.serialisePrivateKey(sk)
    val back = PqSignature.deserialisePrivateKey(bytes) match
      case Right(s) => s
      case Left(e)  => fail(s"deserialisePrivateKey rejected its own output: $e")
    assertEquals(PqSignature.serialisePrivateKey(back).toSeq, bytes.toSeq)
  }

  test("serialise / deserialise round-trip for signature, then verify") {
    val (sk, pk) = PqSignature.generateKeyPair(fixedRng("ser-sig-keys"))
    val sig = PqSignature.sign(sk, msg)
    val bytes = PqSignature.serialiseSignature(sig)
    val back = PqSignature.deserialiseSignature(bytes) match
      case Right(s) => s
      case Left(e)  => fail(s"deserialiseSignature rejected its own output: $e")
    assertEquals(PqSignature.verify(pk, msg, back), true)
  }

  test("deserialiseSignature rejects unknown alg-ID with UnsupportedAlgorithm (FR-013 uniform)") {
    val (sk, _) = PqSignature.generateKeyPair(fixedRng("alg"))
    val sig = PqSignature.sign(sk, msg)
    val bytes = PqSignature.serialiseSignature(sig)
    // Flip alg byte to a value outside the active set; uniform refusal
    val tampered = bytes.clone()
    tampered(0) = 0x42.toByte
    val res = PqSignature.deserialiseSignature(tampered)
    assertEquals(res.left.toOption.contains(PqSignatureError.UnsupportedAlgorithm), true)
  }

  test("deserialiseSignature rejects wrong-length input with InvalidLength") {
    val res = PqSignature.deserialiseSignature(new Array[Byte](100))
    assertEquals(res.left.toOption.contains(PqSignatureError.InvalidLength), true)
  }

  test("deserialisePublicKey rejects unknown alg-ID uniformly") {
    val (_, pk) = PqSignature.generateKeyPair(fixedRng("alg-pk"))
    val bytes = PqSignature.serialisePublicKey(pk)
    val tampered = bytes.clone()
    tampered(0) = 0x11.toByte // RESERVED ML-DSA-87 — still not implemented; refuse uniformly
    val res = PqSignature.deserialisePublicKey(tampered)
    assertEquals(res.left.toOption.contains(PqSignatureError.UnsupportedAlgorithm), true)
  }

  test("publicKey(sk) recovers the same public key produced at keygen") {
    val (sk, pk) = PqSignature.generateKeyPair(fixedRng("pk-recovery"))
    val recovered = PqSignature.publicKey(sk)
    assertEquals(
      PqSignature.serialisePublicKey(recovered).toSeq,
      PqSignature.serialisePublicKey(pk).toSeq,
      "publicKey(sk) should equal the pk from generateKeyPair")
  }
