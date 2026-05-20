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

package siida.mixnet

import java.security.SecureRandom
import munit.FunSuite
import siida.crypto.api.HybridOnion
import siida.mixnet.api.{MixChain, Mixer}

/** Spec 004 — Mixer integrity tests (US2). */
final class MixerSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  test("mixer holding only its own secret CANNOT decrypt another mixer's layer (US2 integrity)") {
    // 3-mixer chain. Build a submission. Then try to peel layer 2
    // with mixer 1's secret — should fail (None).
    val keys = (1 to 3).map(i => HybridOnion.generateBundle(fixedRng(s"mx-$i")))
    val secrets = keys.map(_._1)
    val publics = keys.map(_._2)

    val env = MixChain.envelope(99L, "secret payload".getBytes("UTF-8"))
    val outermost = MixChain.layeredSubmission(publics, env, fixedRng("submit"))

    // Mixer 1 peels successfully — gives us layer 2's bytes
    val layer2Bytes = Mixer.peel(secrets(0), outermost).get
    val layer2 = HybridOnion.deserialiseLayer(layer2Bytes).toOption.get

    // Mixer 1 (holding only secret(0)) tries to peel layer 2:
    // this should FAIL because layer 2 was encrypted to mixer 2's
    // public key. None expected.
    val attempt = Mixer.peel(secrets(0), layer2)
    assertEquals(attempt, None,
      "mixer 1 should not be able to peel mixer 2's layer — HNDL property")
  }

  test("malformed layer (wrong-length bytes) → None (silent drop)") {
    val (secret, _) = HybridOnion.generateBundle(fixedRng("mx-malformed"))
    val (_, public) = HybridOnion.generateBundle(fixedRng("mx-other"))

    val env = MixChain.envelope(0L, "noise".getBytes("UTF-8"))
    val layer = HybridOnion.encrypt(public, MixChain.serialiseEnvelope(env), fixedRng("mx-noise-enc"))
    // Tamper the AEAD ciphertext (last byte) — should fail to decrypt
    val bytes = HybridOnion.serialiseLayer(layer)
    bytes(bytes.length - 1) = (bytes(bytes.length - 1) ^ 0x01).toByte
    val tampered = HybridOnion.deserialiseLayer(bytes).toOption.get
    assertEquals(Mixer.peel(secret, tampered), None)
  }

  test("peel uses the matching secret — round-trip works under correct key") {
    val (secret, public) = HybridOnion.generateBundle(fixedRng("mx-match"))
    val payload = "round-trip payload".getBytes("UTF-8")
    val layer = HybridOnion.encrypt(public, payload, fixedRng("mx-match-enc"))
    val inner = Mixer.peel(secret, layer).get
    assertEquals(inner.toSeq, payload.toSeq)
  }
