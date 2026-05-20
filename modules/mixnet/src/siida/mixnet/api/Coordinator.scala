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

package siida.mixnet.api

import siida.crypto.api.HybridOnion
import siida.mixnet.internal.Shuffle

/** Run one mix round through a chain of mixers. Pure deterministic
 *  function modulo the underlying crypto primitives (FR-003):
 *  given the same submissions + chain secrets + shuffle seeds,
 *  produces the same `RoundResult` byte-for-byte.
 *
 *  This is the MVP coordinator. Production deployment will wrap
 *  this in a Pekko Actor for round-timing + a Pekko Streams
 *  pipeline for the per-mixer transport — both deferred to a
 *  follow-up spec (see plan.md "What 004 does NOT do").
 */
object Coordinator:

  /** One per-round result: ordered output set of mailbox
   *  envelopes plus diagnostic metrics. The order of `deliveries`
   *  is the output order of the LAST mixer (i.e., shuffled
   *  relative to the input).
   */
  final case class RoundResult(
    deliveries: Vector[MixChain.MailboxEnvelope],
    metrics:    RoundMetrics,
  )

  /** Diagnostic counters from one round. Produced post-hoc; no
   *  timing-side-channel concerns since the values are
   *  population-level (not per-submission).
   */
  final case class RoundMetrics(
    submissionsIn:  Int,
    deliveriesOut:  Int,
    perMixerDrops:  Vector[Int],
  )

  /** Run one round.
   *
   *  @param submissions    the outermost OnionLayer bytes from each client
   *  @param chainSecrets   mixer secret bundles, in chain order
   *                        (chainSecrets(0) processes the batch first)
   *  @param shuffleSeeds   32-byte shuffle seed per mixer
   *  @return a `RoundResult` containing the deliveries and metrics
   *
   *  Throws `IllegalArgumentException` on:
   *    - empty chain
   *    - chainSecrets.length != shuffleSeeds.length
   *    - any seed != 32 bytes
   *
   *  Per-submission failures (wire-format error, decryption
   *  failure) drop the submission silently (FR-004).
   */
  def runRound(
    submissions:   Seq[HybridOnion.OnionLayer],
    chainSecrets:  Seq[HybridOnion.HybridSecretBundle],
    shuffleSeeds:  Seq[Array[Byte]],
  ): RoundResult =
    require(chainSecrets.nonEmpty, "Coordinator.runRound: empty chain")
    require(chainSecrets.length == shuffleSeeds.length,
      s"chain length ${chainSecrets.length} != seed count ${shuffleSeeds.length}")
    shuffleSeeds.foreach: s =>
      require(s.length == Shuffle.SeedBytes,
        s"shuffle seed must be ${Shuffle.SeedBytes} bytes, got ${s.length}")

    val totalIn = submissions.length
    val drops = Array.fill(chainSecrets.length)(0)
    // Process the chain: at hop k, peel + shuffle. Result of the
    // last hop is the inner MailboxEnvelope bytes (not another
    // OnionLayer); we collect those as deliveries.
    var batch: Vector[Array[Byte]] = submissions.map(HybridOnion.serialiseLayer).toVector
    var hopIdx = 0
    while hopIdx < chainSecrets.length do
      val secret = chainSecrets(hopIdx)
      val peeled = batch.flatMap { wireBytes =>
        HybridOnion.deserialiseLayer(wireBytes) match
          case Right(layer) =>
            Mixer.peel(secret, layer) match
              case Some(inner) => Some(inner)
              case None        => drops(hopIdx) += 1; None
          case Left(_) =>
            drops(hopIdx) += 1
            None
      }
      batch = Shuffle.shuffle(peeled, shuffleSeeds(hopIdx))
      hopIdx += 1

    // After all hops, `batch` is the inner MailboxEnvelope bytes.
    // We wrap them as the opaque MailboxEnvelope type via a
    // round-tripping deserialise (validates the 8-byte minimum
    // length; failures here are also silent drops).
    val deliveries = batch.flatMap: env =>
      MixChain.deserialiseEnvelope(env).toOption
    val finalDrops = batch.length - deliveries.length
    if finalDrops > 0 then
      drops(chainSecrets.length - 1) += finalDrops

    RoundResult(
      deliveries = deliveries,
      metrics    = RoundMetrics(
        submissionsIn = totalIn,
        deliveriesOut = deliveries.length,
        perMixerDrops = drops.toVector,
      ),
    )
