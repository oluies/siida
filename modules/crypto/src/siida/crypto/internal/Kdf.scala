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

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** HKDF-SHA-256 (RFC 5869) with per-usage domain-separated info
 *  tags. Used by IBE for the message KDF (research R5):
 *
 *    info = "siida/ibe/v1/kdf"
 *
 *  Constant-time over the secret material is delivered by
 *  HmacSHA256; output length is fixed per call (no length-dependent
 *  branching).
 */
object Kdf:

  private val HmacAlg = "HmacSHA256"
  private val HashLen = 32 // SHA-256 output bytes

  /** HKDF Extract-then-Expand. Returns `length` bytes derived from
   *  `ikm` (input keying material) under `salt`, with the `info`
   *  context tag.
   *
   *  Throws IllegalArgumentException on length > 255 * 32 (the
   *  HKDF-SHA-256 upper bound). Programming bug, not a per-call
   *  error.
   */
  def hkdf(
    ikm:    Array[Byte],
    salt:   Array[Byte],
    info:   Array[Byte],
    length: Int,
  ): Array[Byte] =
    require(length > 0 && length <= 255 * HashLen,
      s"HKDF-SHA-256 output length $length out of range (1..${255 * HashLen})")

    val effectiveSalt =
      if salt.length > 0 then salt
      else new Array[Byte](HashLen) // RFC 5869 §2.2: zeros if salt absent

    // Extract: PRK = HMAC(salt, ikm)
    val extractMac = Mac.getInstance(HmacAlg)
    extractMac.init(SecretKeySpec(effectiveSalt, HmacAlg))
    val prk = extractMac.doFinal(ikm)

    // Expand: T(1) | T(2) | ... | T(N), N = ceil(length / 32)
    val expandMac = Mac.getInstance(HmacAlg)
    expandMac.init(SecretKeySpec(prk, HmacAlg))

    val out = new Array[Byte](length)
    val n = (length + HashLen - 1) / HashLen
    var prevT: Array[Byte] = Array.emptyByteArray
    var i = 1
    var written = 0
    while i <= n do
      expandMac.reset()
      expandMac.update(prevT)
      expandMac.update(info)
      expandMac.update(i.toByte)
      val t = expandMac.doFinal()
      val toCopy = math.min(HashLen, length - written)
      System.arraycopy(t, 0, out, written, toCopy)
      written += toCopy
      prevT = t
      i += 1

    out

  /** Convenience: IBE message KDF, info = `"siida/ibe/v1/kdf"`. */
  def ibeKdf(ikm: Array[Byte], length: Int): Array[Byte] =
    hkdf(
      ikm    = ikm,
      salt   = Array.emptyByteArray,
      info   = "siida/ibe/v1/kdf".getBytes("US-ASCII"),
      length = length,
    )
