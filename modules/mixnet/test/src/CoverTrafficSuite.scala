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
import siida.mixnet.api.{Coordinator, MixChain}

/** Spec 004 US3 — cover-traffic indistinguishability tests. */
final class CoverTrafficSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private def seed(label: String): Array[Byte] =
    val rng = fixedRng(label)
    val out = new Array[Byte](32)
    rng.nextBytes(out)
    out

  test("4 real + 4 cover submissions are all delivered, with covers targeting the reserved id") {
    val pairs = (1 to 3).map(i => HybridOnion.generateBundle(fixedRng(s"ctsuite-mixer-$i")))
    val chainSecrets = pairs.map(_._1)
    val chainPublics = pairs.map(_._2)

    val payloadLen = 128

    val real = (1L to 4L).map { i =>
      val env = MixChain.envelope(i + 100L, new Array[Byte](payloadLen))
      MixChain.layeredSubmission(chainPublics, env, fixedRng(s"ct-real-$i"))
    }
    val cover = (1 to 4).map: i =>
      MixChain.coverSubmission(chainPublics, payloadLen, fixedRng(s"ct-cover-$i"))

    val submissions = real ++ cover
    val seeds = (1 to 3).map(i => seed(s"ct-shuffle-$i"))

    val result = Coordinator.runRound(submissions, chainSecrets, seeds)
    assertEquals(result.metrics.submissionsIn, 8)
    assertEquals(result.metrics.deliveriesOut, 8)

    val realIds = result.deliveries.map(MixChain.envelopeMailboxId).filter(_ != 0L).sorted
    val coverCount = result.deliveries.count(env => MixChain.envelopeMailboxId(env) == 0L)
    assertEquals(realIds, Vector(101L, 102L, 103L, 104L))
    assertEquals(coverCount, 4, "expected 4 cover deliveries (mailbox_id = 0)")
  }

  test("cover and real submissions have identical wire lengths for the same payload size (FR-007)") {
    val pairs = (1 to 3).map(i => HybridOnion.generateBundle(fixedRng(s"frlen-mixer-$i")))
    val publics = pairs.map(_._2)
    val payloadLen = 256

    val coverWireLen = HybridOnion.serialiseLayer(
      MixChain.coverSubmission(publics, payloadLen, fixedRng("frlen-cover"))).length
    val realWireLen = HybridOnion.serialiseLayer(
      MixChain.layeredSubmission(publics,
        MixChain.envelope(7L, new Array[Byte](payloadLen)),
        fixedRng("frlen-real"))).length
    assertEquals(coverWireLen, realWireLen,
      "cover and real wire lengths must match (FR-007 indistinguishability)")
  }
