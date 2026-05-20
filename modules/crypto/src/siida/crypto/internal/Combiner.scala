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

package siida.crypto.internal

import java.security.MessageDigest

/** SHA3-256 hybrid combiner per spec 012-pq-mixnet-onion-layer
 *  research R3:
 *
 *    combined = SHA3-256(classical_ss || ml_kem_ss || DST)
 *
 *  The 32-byte output is the AEAD key for the onion-layer
 *  encryption. Security is `max(classical, PQ)`: an adversary who
 *  breaks only one half cannot distinguish the output from random.
 *
 *  DST values are per-usage to prevent cross-protocol confusion.
 *  New usages MUST add a new constant rather than reusing
 *  `OnionLayerDST`.
 */
object Combiner:

  /** Domain-separation tag for the 012 onion-layer hybrid. */
  val OnionLayerDST: Array[Byte] =
    "siida/hybrid/v1/onion-layer".getBytes("US-ASCII")

  /** Combine two shared secrets under a domain-separation tag.
   *  Output is 32 bytes (SHA3-256 digest).
   */
  def combine(
    classicalSs: Array[Byte],
    mlKemSs:     Array[Byte],
    dst:         Array[Byte],
  ): Array[Byte] =
    val sha3 = MessageDigest.getInstance("SHA3-256")
    sha3.update(classicalSs)
    sha3.update(mlKemSs)
    sha3.update(dst)
    sha3.digest()
