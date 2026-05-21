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
import siida.observability.api.Telemetry

/** Spec 021 — Coordinator records round metrics via the
 *  optional Telemetry parameter.
 */
final class CoordinatorTelemetrySuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private def mkChain(label: String, n: Int): (Vector[HybridOnion.HybridSecretBundle], Vector[HybridOnion.HybridPublicBundle]) =
    val pairs = (0 until n).map(i => HybridOnion.generateBundle(fixedRng(s"$label-mix-$i"))).toVector
    (pairs.map(_._1), pairs.map(_._2))

  test("SC-001: records submissions/deliveries/drops for a happy-path round") {
    val (mixSks, mixPks) = mkChain("hp", 2)
    val rng = fixedRng("hp-snd")
    val submissions = (0 until 4).map { _ =>
      val env = MixChain.envelope(99L, "x".getBytes("UTF-8"))
      MixChain.layeredSubmission(mixPks, env, rng)
    }.toVector
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x44.toByte))
    val tel = Telemetry.inMemory()
    val result = Coordinator.runRound(submissions, mixSks, seeds, tel)
    assertEquals(result.deliveries.length, 4)
    val s = tel.snapshot()
    assertEquals(s.counters("mixnet.round.submissions"), 4L)
    assertEquals(s.counters("mixnet.round.deliveries"), 4L)
    assertEquals(s.counters.getOrElse("mixnet.round.drops_per_mixer.0", 0L), 0L)
    assertEquals(s.counters.getOrElse("mixnet.round.drops_per_mixer.1", 0L), 0L)
    assertEquals(s.histograms("mixnet.round.drops"), Vector(0.0))
  }

  test("records non-zero drops_per_mixer when an outer-layer is wrong-keyed") {
    val (mixSks, mixPks) = mkChain("drop", 2)
    // Build a "bad" submission whose outer layer was encrypted to a
    // mixer key not in the configured chain → first mixer fails to peel.
    val (_, foreignPks) = mkChain("foreign", 2)
    val rng = fixedRng("drop-snd")
    val env = MixChain.envelope(7L, "ok".getBytes("UTF-8"))
    val good = MixChain.layeredSubmission(mixPks, env, rng)
    val bad  = MixChain.layeredSubmission(foreignPks, env, rng)
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x55.toByte))
    val tel = Telemetry.inMemory()
    val result = Coordinator.runRound(Vector(good, bad), mixSks, seeds, tel)
    assertEquals(result.deliveries.length, 1)
    val s = tel.snapshot()
    assertEquals(s.counters("mixnet.round.submissions"), 2L)
    assertEquals(s.counters("mixnet.round.deliveries"), 1L)
    // Total drops = 1, recorded as a single histogram entry of 1.0
    assertEquals(s.histograms("mixnet.round.drops"), Vector(1.0))
  }

  test("Telemetry.noop default keeps the API backward-compatible (no extra param)") {
    val (mixSks, mixPks) = mkChain("noop", 2)
    val env = MixChain.envelope(1L, "a".getBytes("UTF-8"))
    val sub = MixChain.layeredSubmission(mixPks, env, fixedRng("noop-snd"))
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x66.toByte))
    // No telemetry argument — defaults to Telemetry.noop
    val result = Coordinator.runRound(Vector(sub), mixSks, seeds)
    assertEquals(result.deliveries.length, 1)
  }
