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

package siida.mixnet.internal

import java.security.SecureRandom

/** Deterministic Fisher-Yates shuffle seeded from a 32-byte
 *  buffer. Used by each mixer to permute the batch after peeling
 *  one onion layer (spec 004 FR-005). Same seed → same
 *  permutation across JVMs (SHA1PRNG is bit-stable per the Java
 *  standard).
 */
object Shuffle:

  inline val SeedBytes = 32

  /** Shuffle a sequence in place. Returns a NEW Vector — does not
   *  mutate the input.
   */
  def shuffle[A](batch: Seq[A], seed: Array[Byte]): Vector[A] =
    require(seed.length == SeedBytes,
      s"Shuffle.shuffle: seed must be $SeedBytes bytes, got ${seed.length}")
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(seed)
    // Materialise indices, shuffle the indices, then permute the
    // input — avoids needing a ClassTag for A.
    val indices = scala.collection.mutable.ArrayBuffer.tabulate(batch.length)(identity)
    var i = indices.length - 1
    while i > 0 do
      val j = rng.nextInt(i + 1)
      val tmp = indices(i); indices(i) = indices(j); indices(j) = tmp
      i -= 1
    val src = batch.toIndexedSeq
    indices.iterator.map(src.apply).toVector
