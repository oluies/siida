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
import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import munit.FunSuite
import siida.crypto.internal.{Combiner, HybridOnionWire, X25519}

/** Spec 012 US1 — round-trip + HNDL-resistance + serialisation
 *  round-trips for the hybrid mixnet onion layer.
 */
final class HybridOnionSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private val payload = "hello PQ siida".getBytes("UTF-8")

  test("round-trip: encrypt → decrypt recovers the original payload byte-for-byte") {
    val (secret, public) = HybridOnion.generateBundle(fixedRng("hybrid/rt-keys"))
    val layer = HybridOnion.encrypt(public, payload, fixedRng("hybrid/rt-encrypt"))
    val recovered = HybridOnion.decrypt(secret, layer) match
      case Right(p) => p
      case Left(e)  => fail(s"decrypt returned Left($e)")
    assertEquals(recovered.toSeq, payload.toSeq,
      "round-trip plaintext mismatch")
  }

  test("HNDL-resistance: classical-only decapsulation MUST fail (FR-008)") {
    // Construct a recipient bundle, encrypt to it, then simulate a
    // quantum adversary who has somehow recovered the recipient's
    // x25519 secret key (via Shor) but does NOT have the recipient's
    // ML-KEM secret key. The adversary can compute the classical
    // shared secret but not the ML-KEM half.
    val (secret, public) = HybridOnion.generateBundle(fixedRng("hndl/keys"))
    val layer = HybridOnion.encrypt(public, payload, fixedRng("hndl/encrypt"))

    // Unpack the wire envelope to get the ephemeral pk + ML-KEM ct
    // + AEAD ct+tag.
    val layerBytes = HybridOnion.serialiseLayer(layer)
    val (_, ephPk, _, aeadCtTag) = HybridOnionWire.unpack(layerBytes) match
      case Right(t) => t
      case Left(e)  => fail(s"unpack failed: $e")

    // Adversary computes the REAL classical share (using recovered
    // x25519_sk + the wire's ephemeral pk).
    val recipientX25519Sk = HybridOnion.serialiseSecretBundle(secret)
      .take(X25519.ScalarBytes)
    val classicalSs = X25519.ecdh(recipientX25519Sk, ephPk) match
      case Right(ss) => ss
      case Left(e)   => fail(s"adversary's ECDH failed: $e")

    // Adversary tries an arbitrary 32-byte stand-in for the
    // unknown ML-KEM shared secret. Use all-zeros (representing
    // any guess the adversary makes).
    val guessedMlKemSs = new Array[Byte](32)

    val adversaryKey = Combiner.combine(classicalSs, guessedMlKemSs, Combiner.OnionLayerDST)
    val singleLayerNonce = new Array[Byte](12)

    val cipher = Cipher.getInstance("ChaCha20-Poly1305")
    cipher.init(
      Cipher.DECRYPT_MODE,
      SecretKeySpec(adversaryKey, "ChaCha20"),
      IvParameterSpec(singleLayerNonce),
    )

    // The AEAD decryption MUST fail — the adversary's key is wrong
    // (combiner output is different without the real ML-KEM share).
    val decryptOutcome =
      try
        cipher.doFinal(aeadCtTag)
        "succeeded"
      catch
        case _: javax.crypto.AEADBadTagException => "failed-as-expected"
        case other: Throwable                    => s"failed-with-other:${other.getClass.getSimpleName}"

    assertEquals(decryptOutcome, "failed-as-expected",
      "AEAD decryption with classical-only share succeeded — HNDL resistance is broken!")
  }

  test("encrypt is deterministic under fixed-seed RNG") {
    val (_, public1) = HybridOnion.generateBundle(fixedRng("det/keys"))
    val (_, public2) = HybridOnion.generateBundle(fixedRng("det/keys"))
    val pk1 = HybridOnion.serialisePublicBundle(public1)
    val pk2 = HybridOnion.serialisePublicBundle(public2)
    assertEquals(pk1.toSeq, pk2.toSeq,
      "HybridOnion.generateBundle non-deterministic from fixed seed")

    val layer1 = HybridOnion.serialiseLayer(
      HybridOnion.encrypt(public1, payload, fixedRng("det/encrypt")))
    val layer2 = HybridOnion.serialiseLayer(
      HybridOnion.encrypt(public2, payload, fixedRng("det/encrypt")))
    assertEquals(layer1.toSeq, layer2.toSeq,
      "HybridOnion.encrypt non-deterministic from fixed seed")
  }

  test("serialise / deserialise round-trip for public bundle") {
    val (_, public) = HybridOnion.generateBundle(fixedRng("ser/pub"))
    val bytes = HybridOnion.serialisePublicBundle(public)
    assertEquals(bytes.length, 1216, "public bundle wire size mismatch")
    val back = HybridOnion.deserialisePublicBundle(bytes) match
      case Right(p) => p
      case Left(e)  => fail(s"deserialise rejected our own bytes: $e")
    assertEquals(HybridOnion.serialisePublicBundle(back).toSeq, bytes.toSeq)
  }

  test("serialise / deserialise round-trip for secret bundle") {
    val (secret, _) = HybridOnion.generateBundle(fixedRng("ser/sec"))
    val bytes = HybridOnion.serialiseSecretBundle(secret)
    assertEquals(bytes.length, 2432, "secret bundle wire size mismatch")
    val back = HybridOnion.deserialiseSecretBundle(bytes) match
      case Right(s) => s
      case Left(e)  => fail(s"deserialise rejected our own bytes: $e")
    assertEquals(HybridOnion.serialiseSecretBundle(back).toSeq, bytes.toSeq)
  }

  test("serialise / deserialise round-trip for an onion layer, then decrypt") {
    val (secret, public) = HybridOnion.generateBundle(fixedRng("ser/layer-keys"))
    val layer = HybridOnion.encrypt(public, payload, fixedRng("ser/layer-encrypt"))
    val bytes = HybridOnion.serialiseLayer(layer)
    HybridOnion.deserialiseLayer(bytes) match
      case Right(layer2) =>
        HybridOnion.decrypt(secret, layer2) match
          case Right(recovered) =>
            assertEquals(recovered.toSeq, payload.toSeq)
          case Left(e) => fail(s"decrypt of deserialised layer failed: $e")
      case Left(e) => fail(s"deserialise rejected our own bytes: $e")
  }

  test("deserialiseLayer rejects too-short input with InvalidLength") {
    val res = HybridOnion.deserialiseLayer(new Array[Byte](100))
    assertEquals(res, Left(HybridOnionError.InvalidLength))
  }

  test("deserialiseLayer rejects unknown algorithm ID with UnsupportedAlgorithm") {
    val (_, public) = HybridOnion.generateBundle(fixedRng("alg/keys"))
    val layer = HybridOnion.encrypt(public, payload, fixedRng("alg/encrypt"))
    val bytes = HybridOnion.serialiseLayer(layer)
    val tampered = bytes.clone()
    tampered(0) = 0x42.toByte // unknown alg ID
    val res = HybridOnion.deserialiseLayer(tampered)
    assertEquals(res, Left(HybridOnionError.UnsupportedAlgorithm))
  }
