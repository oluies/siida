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
import siida.crypto.internal.MlKem

/** Smoke tests for the Bouncy Castle ML-KEM-768 wrapper. Verifies
 *  keygen + encap + decap round-trip, byte-size invariants, and
 *  determinism under fixed-seed RNG. External KATs (NIST CAVS or
 *  similar) deferred to a follow-up.
 */
final class MlKem768Suite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  test("keygen produces public key of 1184 bytes and secret key of 2400 bytes") {
    val (sk, pk) = MlKem.keygen(fixedRng("mlkem/sizes"))
    assertEquals(sk.length, MlKem.SecretKeyBytes)
    assertEquals(pk.length, MlKem.PublicKeyBytes)
  }

  test("encap produces a 1088-byte ciphertext and a 32-byte shared secret") {
    val (_, pk) = MlKem.keygen(fixedRng("mlkem/encap-keys"))
    val (ct, ss) = MlKem.encap(pk, fixedRng("mlkem/encap-rng"))
    assertEquals(ct.length, MlKem.CiphertextBytes)
    assertEquals(ss.length, MlKem.SharedSecretBytes)
  }

  test("decap recovers the same shared secret as encap") {
    val (sk, pk) = MlKem.keygen(fixedRng("mlkem/roundtrip-keys"))
    val (ct, ssEncap) = MlKem.encap(pk, fixedRng("mlkem/roundtrip-rng"))
    val ssDecap = MlKem.decap(sk, ct) match
      case Right(ss) => ss
      case Left(err) => fail(s"decap returned Left($err)")
    assertEquals(ssDecap.toSeq, ssEncap.toSeq, "encap/decap shared secrets differ")
  }

  test("decap rejects truncated ciphertext with InvalidLength") {
    val (sk, _) = MlKem.keygen(fixedRng("mlkem/short-ct"))
    val tooShort = new Array[Byte](100)
    val res = MlKem.decap(sk, tooShort)
    assert(res.isLeft, s"expected Left for short ciphertext, got $res")
  }

  test("determinism: same SHA1PRNG seed → byte-identical keypair") {
    val (sk1, pk1) = MlKem.keygen(fixedRng("mlkem/determinism"))
    val (sk2, pk2) = MlKem.keygen(fixedRng("mlkem/determinism"))
    assertEquals(sk1.toSeq, sk2.toSeq, "ML-KEM keygen non-deterministic from same seed")
    assertEquals(pk1.toSeq, pk2.toSeq, "ML-KEM pk non-deterministic from same seed")
  }
