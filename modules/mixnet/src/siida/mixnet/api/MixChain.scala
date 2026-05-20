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

import java.security.SecureRandom
import siida.crypto.api.HybridOnion

/** Client-side layered-encryption helper. Builds and decodes the
 *  N-layer onion submission that flows through the mixer chain.
 *
 *  Wire format: spec 004's `contracts/wire-format.md`.
 *  - Each layer is a `HybridOnion.OnionLayer` (1137-byte fixed
 *    overhead + AEAD ciphertext).
 *  - Innermost payload is a `MailboxEnvelope`:
 *    8-byte big-endian mailbox_id + opaque payload.
 */
object MixChain:

  opaque type MailboxEnvelope = Array[Byte]

  /** Reserved mailbox-id for cover traffic. */
  val CoverMailboxId: Long = 0L

  /** Reserved mailbox-id for future broadcast semantics. */
  val BroadcastMailboxId: Long = -1L

  inline val MailboxIdBytes = 8

  // ── Envelope construction / accessors ───────────────────────────

  /** Build a `MailboxEnvelope` from id + payload. */
  def envelope(mailboxId: Long, payload: Array[Byte]): MailboxEnvelope =
    val out = new Array[Byte](MailboxIdBytes + payload.length)
    writeMailboxId(out, 0, mailboxId)
    System.arraycopy(payload, 0, out, MailboxIdBytes, payload.length)
    out

  def envelopeMailboxId(env: MailboxEnvelope): Long =
    require(env.length >= MailboxIdBytes, "envelope too short")
    readMailboxId(env, 0)

  def envelopePayload(env: MailboxEnvelope): Array[Byte] =
    require(env.length >= MailboxIdBytes, "envelope too short")
    java.util.Arrays.copyOfRange(env, MailboxIdBytes, env.length)

  /** Serialise an envelope to its on-wire byte representation
   *  (which is just the underlying array). Exposed so callers
   *  (e.g., tests, the SDK) can build envelopes for transport.
   */
  def serialiseEnvelope(env: MailboxEnvelope): Array[Byte] = env.clone()

  /** Parse on-wire bytes into a `MailboxEnvelope`. */
  def deserialiseEnvelope(bytes: Array[Byte]): Either[MixnetError, MailboxEnvelope] =
    if bytes.length < MailboxIdBytes then Left(MixnetError.InvalidLength)
    else Right(bytes.clone())

  // ── Layered submission ───────────────────────────────────────

  /** Build a layered submission for a chain of mixers. The first
   *  mixer's public bundle is `chain.head` (the outermost layer);
   *  the last mixer's bundle is `chain.last` (the innermost).
   *
   *  The output is the outermost OnionLayer — what the client
   *  submits to the coordinator.
   *
   *  Algorithm (bottom-up):
   *    cipher_0 = envelope bytes
   *    cipher_k = HybridOnion.encrypt(chain[N-k], cipher_{k-1}, rng)  for k = 1..N
   *
   *  Throws `IllegalArgumentException` on empty chain (programming bug).
   */
  def layeredSubmission(
    chain:    Seq[HybridOnion.HybridPublicBundle],
    envelope: MailboxEnvelope,
    rng:      SecureRandom,
  ): HybridOnion.OnionLayer =
    require(chain.nonEmpty, "MixChain.layeredSubmission: empty chain")
    // The innermost payload (envelope bytes) is encrypted under
    // the LAST mixer in the chain first, then each prior mixer
    // wraps that ciphertext. Fold from the innermost (last mixer)
    // out: result of each step is the OnionLayer for that hop.
    val reversed = chain.reverse
    val first    = HybridOnion.encrypt(reversed.head, envelope, rng)
    reversed.tail.foldLeft(first) { (innerLayer, mixerPk) =>
      val innerBytes = HybridOnion.serialiseLayer(innerLayer)
      HybridOnion.encrypt(mixerPk, innerBytes, rng)
    }

  /** Cover-traffic submission. Targets the reserved
   *  `CoverMailboxId` with `payloadLen` random bytes. On-wire
   *  indistinguishable from a real submission of the same payload
   *  size (FR-007).
   */
  def coverSubmission(
    chain:      Seq[HybridOnion.HybridPublicBundle],
    payloadLen: Int,
    rng:        SecureRandom,
  ): HybridOnion.OnionLayer =
    require(payloadLen >= 0, "payloadLen must be non-negative")
    val payload = new Array[Byte](payloadLen)
    rng.nextBytes(payload)
    val env = envelope(CoverMailboxId, payload)
    layeredSubmission(chain, env, rng)

  // ── Internal big-endian readers ─────────────────────────────

  private def writeMailboxId(buf: Array[Byte], off: Int, id: Long): Unit =
    var i = 0
    while i < MailboxIdBytes do
      buf(off + i) = ((id >>> ((MailboxIdBytes - 1 - i) * 8)) & 0xFF).toByte
      i += 1

  private def readMailboxId(buf: Array[Byte], off: Int): Long =
    var id: Long = 0L
    var i = 0
    while i < MailboxIdBytes do
      id = (id << 8) | (buf(off + i).toLong & 0xFFL)
      i += 1
    id
