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

/** Spec 004 — MixChain (client-side layered encryption). */
final class MixChainSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  test("envelope round-trip: build → read mailbox_id and payload") {
    val payload = "hello mailbox".getBytes("UTF-8")
    val env = MixChain.envelope(42L, payload)
    assertEquals(MixChain.envelopeMailboxId(env), 42L)
    assertEquals(MixChain.envelopePayload(env).toSeq, payload.toSeq)
  }

  test("envelope reserved IDs surface as the documented constants") {
    assertEquals(MixChain.CoverMailboxId, 0L)
    assertEquals(MixChain.BroadcastMailboxId, -1L) // == 0xFFFF…FFFF as signed Long
  }

  test("layered submission peels back through the chain to recover the envelope") {
    // 3-mixer chain
    val chainSecretsAndPublics = (1 to 3).map: i =>
      HybridOnion.generateBundle(fixedRng(s"mixer-$i"))
    val chainSecrets = chainSecretsAndPublics.map(_._1)
    val chainPublics = chainSecretsAndPublics.map(_._2)

    val payload = "siida 004 end-to-end".getBytes("UTF-8")
    val env = MixChain.envelope(7L, payload)

    val outermostLayer = MixChain.layeredSubmission(
      chainPublics, env, fixedRng("client-submission"),
    )

    // Peel: hop 1 (mixer 1's secret), hop 2 (mixer 2's secret),
    // hop 3 (mixer 3's secret). Final output is the envelope bytes.
    val l1bytes = HybridOnion.serialiseLayer(outermostLayer)
    val l1      = HybridOnion.deserialiseLayer(l1bytes).toOption.get
    val l2bytes = Mixer.peel(chainSecrets(0), l1).get
    val l2      = HybridOnion.deserialiseLayer(l2bytes).toOption.get
    val l3bytes = Mixer.peel(chainSecrets(1), l2).get
    val l3      = HybridOnion.deserialiseLayer(l3bytes).toOption.get
    val envBytes = Mixer.peel(chainSecrets(2), l3).get

    val recovered = MixChain.deserialiseEnvelope(envBytes).toOption.get
    assertEquals(MixChain.envelopeMailboxId(recovered), 7L)
    assertEquals(MixChain.envelopePayload(recovered).toSeq, payload.toSeq)
  }

  test("cover submission targets CoverMailboxId and on-wire matches a real submission of same payload length") {
    val chainSecretsAndPublics = (1 to 3).map(i =>
      HybridOnion.generateBundle(fixedRng(s"mixer-$i")))
    val chainSecrets = chainSecretsAndPublics.map(_._1)
    val chainPublics = chainSecretsAndPublics.map(_._2)

    val payloadLen = 256
    val coverLayer = MixChain.coverSubmission(
      chainPublics, payloadLen, fixedRng("cover-1"),
    )
    val realEnv = MixChain.envelope(42L, new Array[Byte](payloadLen))
    val realLayer = MixChain.layeredSubmission(
      chainPublics, realEnv, fixedRng("cover-2"),
    )

    // Same wire-format byte length (no fingerprint)
    assertEquals(
      HybridOnion.serialiseLayer(coverLayer).length,
      HybridOnion.serialiseLayer(realLayer).length,
      "cover and real submission wire lengths must match (FR-007)")

    // Peel cover all the way to verify it targets CoverMailboxId
    var bytes: Array[Byte] = HybridOnion.serialiseLayer(coverLayer)
    chainSecrets.foreach { s =>
      val layer = HybridOnion.deserialiseLayer(bytes).toOption.get
      bytes = Mixer.peel(s, layer).get
    }
    val env = MixChain.deserialiseEnvelope(bytes).toOption.get
    assertEquals(MixChain.envelopeMailboxId(env), MixChain.CoverMailboxId)
  }

  test("deserialiseEnvelope rejects too-short input with InvalidLength") {
    val res = MixChain.deserialiseEnvelope(new Array[Byte](4))
    assert(res.isLeft, "expected Left(InvalidLength)")
  }
