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

/** Spec 004 — Coordinator end-to-end round tests (US1). */
final class RoundSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private def seed(label: String): Array[Byte] =
    val rng = fixedRng(label)
    val out = new Array[Byte](32)
    rng.nextBytes(out)
    out

  /** Build a 3-mixer chain. Returns (secrets, publics). */
  private def mixerChain(): (Seq[HybridOnion.HybridSecretBundle], Seq[HybridOnion.HybridPublicBundle]) =
    val pairs = (1 to 3).map(i => HybridOnion.generateBundle(fixedRng(s"chain-mixer-$i")))
    (pairs.map(_._1), pairs.map(_._2))

  test("8-client / 3-mixer round delivers every plaintext to the right mailbox (US1 SC-001)") {
    val (chainSecrets, chainPublics) = mixerChain()
    // 8 clients: each picks a distinct mailbox-id and unique plaintext
    val inputs = (1L to 8L).map { i =>
      val env = MixChain.envelope(i, s"message-from-client-$i".getBytes("UTF-8"))
      val outermost = MixChain.layeredSubmission(
        chainPublics, env, fixedRng(s"client-$i"),
      )
      (i, env, outermost)
    }
    val submissions = inputs.map(_._3)
    val seeds = (1 to 3).map(i => seed(s"shuffle-$i"))

    val result = Coordinator.runRound(submissions, chainSecrets, seeds)
    assertEquals(result.metrics.submissionsIn, 8)
    assertEquals(result.metrics.deliveriesOut, 8)
    assertEquals(result.metrics.perMixerDrops, Vector(0, 0, 0))

    // Every input mailbox-id should appear in the output, with
    // the matching payload. Order is shuffle-dependent.
    val expectedSet = inputs.map((id, env, _) => (id, MixChain.envelopePayload(env).toSeq)).toSet
    val actualSet = result.deliveries.map { env =>
      (MixChain.envelopeMailboxId(env), MixChain.envelopePayload(env).toSeq)
    }.toSet
    assertEquals(actualSet, expectedSet)
  }

  test("runRound is deterministic given fixed seeds (SC-002)") {
    val (chainSecrets, chainPublics) = mixerChain()
    val submissions = (1L to 4L).map { i =>
      val env = MixChain.envelope(i, s"det-$i".getBytes("UTF-8"))
      MixChain.layeredSubmission(chainPublics, env, fixedRng(s"det-client-$i"))
    }
    val seeds = (1 to 3).map(i => seed(s"det-shuffle-$i"))

    val r1 = Coordinator.runRound(submissions, chainSecrets, seeds)
    val r2 = Coordinator.runRound(submissions, chainSecrets, seeds)
    // Byte-for-byte equal output ordering
    assertEquals(
      r1.deliveries.map(MixChain.serialiseEnvelope(_).toSeq),
      r2.deliveries.map(MixChain.serialiseEnvelope(_).toSeq),
      "two runs with same inputs must produce byte-identical output")
  }

  test("corrupted submission is dropped at the first mixer; the rest deliver (SC-003)") {
    val (chainSecrets, chainPublics) = mixerChain()
    val inputs = (1L to 4L).map { i =>
      val env = MixChain.envelope(i, s"clean-$i".getBytes("UTF-8"))
      MixChain.layeredSubmission(chainPublics, env, fixedRng(s"corrupt-$i"))
    }
    // Tamper input #2's outermost layer (flip a byte in its AEAD ct).
    val bytes = HybridOnion.serialiseLayer(inputs(1))
    bytes(bytes.length - 1) = (bytes(bytes.length - 1) ^ 0x01).toByte
    val tampered = HybridOnion.deserialiseLayer(bytes).toOption.get
    val submissions = inputs.updated(1, tampered)
    val seeds = (1 to 3).map(i => seed(s"corrupt-shuffle-$i"))

    val result = Coordinator.runRound(submissions, chainSecrets, seeds)
    assertEquals(result.metrics.submissionsIn, 4)
    assertEquals(result.metrics.deliveriesOut, 3)
    assertEquals(result.metrics.perMixerDrops, Vector(1, 0, 0),
      "first mixer should record the one drop")
  }

  test("empty round delivers an empty output set (edge case)") {
    val (chainSecrets, _) = mixerChain()
    val seeds = (1 to 3).map(i => seed(s"empty-shuffle-$i"))
    val result = Coordinator.runRound(Seq.empty, chainSecrets, seeds)
    assertEquals(result.metrics.submissionsIn, 0)
    assertEquals(result.metrics.deliveriesOut, 0)
    assertEquals(result.deliveries, Vector.empty)
  }

  test("performance: 8-client / 3-mixer / 256-byte round completes well under 500 ms (SC-004)") {
    val (chainSecrets, chainPublics) = mixerChain()
    val submissions = (1L to 8L).map { i =>
      val env = MixChain.envelope(i, new Array[Byte](256))
      MixChain.layeredSubmission(chainPublics, env, fixedRng(s"perf-$i"))
    }
    val seeds = (1 to 3).map(i => seed(s"perf-shuffle-$i"))

    val t0 = System.nanoTime()
    val result = Coordinator.runRound(submissions, chainSecrets, seeds)
    val elapsedMs = (System.nanoTime() - t0) / 1_000_000.0

    assertEquals(result.metrics.deliveriesOut, 8)
    assert(elapsedMs < 500.0, s"round took ${elapsedMs} ms (>500 ms target)")
  }
