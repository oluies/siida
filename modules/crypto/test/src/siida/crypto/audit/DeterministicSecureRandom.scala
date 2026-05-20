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

package siida.crypto.audit

import java.security.SecureRandom

/** A SecureRandom that returns bytes from a pre-loaded buffer.
 *
 *  Used by the 016 audit suites to inject NIST ACVP fixed-input
 *  randomness into Bouncy Castle's `KyberKeyPairGenerator`,
 *  `KyberKEMGenerator`, `DilithiumKeyPairGenerator`, and
 *  `DilithiumSigner` — none of which expose a deterministic-seed
 *  API directly, but all of which pull their randomness via
 *  `SecureRandom.nextBytes(byte[])`.
 *
 *  Throws if a caller tries to pull more bytes than the buffer
 *  contains — that signals an unexpected internal randomness use
 *  that the audit should surface, not silently mask.
 */
final class DeterministicSecureRandom(buf: Array[Byte]) extends SecureRandom:
  private var pos: Int = 0

  override def nextBytes(out: Array[Byte]): Unit =
    if pos + out.length > buf.length then
      throw RuntimeException(
        s"DeterministicSecureRandom exhausted: need ${out.length} more bytes " +
        s"at offset $pos, buffer has ${buf.length}.")
    System.arraycopy(buf, pos, out, 0, out.length)
    pos += out.length

  def bytesConsumed: Int = pos

  def bytesRemaining: Int = buf.length - pos
