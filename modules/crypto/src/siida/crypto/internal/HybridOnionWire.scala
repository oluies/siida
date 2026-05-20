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

import siida.crypto.api.HybridOnionError

/** Wire-format codec for the 012 hybrid onion-layer envelope, per
 *  `specs/012-pq-mixnet-onion-layer/contracts/wire-format.md`:
 *
 *  ```
 *  offset  size    field
 *  0       1       algorithm ID (0x01 for this spec)
 *  1       32      x25519 ephemeral public key
 *  33      1088    ML-KEM-768 ciphertext
 *  1121    N       ChaCha20-Poly1305 ciphertext-and-tag
 *  ```
 *
 *  Fixed overhead: 1 + 32 + 1088 + 16 = 1137 bytes.
 *
 *  All fields are positional. Length-prefixing is intentionally
 *  absent because the per-algorithm sizes are fixed by FIPS 203 and
 *  X25519 spec; a new variant gets a new algorithm-ID byte and a new
 *  fixed layout.
 */
object HybridOnionWire:

  inline val AlgIdBytes        = 1
  inline val X25519PkBytes     = 32
  inline val MlKemCtBytes      = 1088
  inline val Poly1305TagBytes  = 16
  inline val FixedOverheadBytes = 1137 // AlgIdBytes + X25519PkBytes + MlKemCtBytes + Poly1305TagBytes

  /** Algorithm ID for the hybrid ML-KEM-768 + x25519 variant
   *  defined by this spec.
   */
  val AlgHybridV1: Byte = 0x01

  /** Reserved value for the deprecated classical NaCl `box` variant.
   *  New code MUST NOT emit this; deserialise rejects it.
   */
  val AlgDeprecatedClassical: Byte = 0x00

  /** Serialise the four positional fields into the wire envelope.
   *  Caller is responsible for matching the FIPS 203 / x25519 / AEAD
   *  byte sizes; the function only checks for the fixed-size fields,
   *  not the trailing AEAD ciphertext+tag length (it can vary with
   *  inner payload size).
   */
  def pack(
    algId:     Byte,
    ephPk:     Array[Byte],
    mlKemCt:   Array[Byte],
    aeadCtTag: Array[Byte],
  ): Array[Byte] =
    require(ephPk.length == X25519PkBytes,
      s"HybridOnionWire.pack: ephPk must be $X25519PkBytes bytes, got ${ephPk.length}")
    require(mlKemCt.length == MlKemCtBytes,
      s"HybridOnionWire.pack: mlKemCt must be $MlKemCtBytes bytes, got ${mlKemCt.length}")
    require(aeadCtTag.length >= Poly1305TagBytes,
      s"HybridOnionWire.pack: aeadCtTag must be >= $Poly1305TagBytes bytes, got ${aeadCtTag.length}")

    val total = AlgIdBytes + X25519PkBytes + MlKemCtBytes + aeadCtTag.length
    val out = new Array[Byte](total)
    out(0) = algId
    System.arraycopy(ephPk, 0, out, AlgIdBytes, X25519PkBytes)
    System.arraycopy(mlKemCt, 0, out, AlgIdBytes + X25519PkBytes, MlKemCtBytes)
    System.arraycopy(aeadCtTag, 0, out, AlgIdBytes + X25519PkBytes + MlKemCtBytes, aeadCtTag.length)
    out

  /** Deserialise the wire envelope. Rejects:
   *    - too-short input              → InvalidLength
   *    - unknown algorithm ID         → UnsupportedAlgorithm (uniform; FR-006)
   *  Returns the four positional slices on success.
   */
  def unpack(bytes: Array[Byte]): Either[HybridOnionError, (Byte, Array[Byte], Array[Byte], Array[Byte])] =
    if bytes.length < FixedOverheadBytes then
      Left(HybridOnionError.InvalidLength)
    else
      val algId = bytes(0)
      if algId != AlgHybridV1 then
        // Uniform refusal: deprecated 0x00 and any unknown ID land here
        // with the same error type. No side-channel on which ID was
        // rejected.
        Left(HybridOnionError.UnsupportedAlgorithm)
      else
        val ephPkStart = AlgIdBytes
        val mlKemCtStart = ephPkStart + X25519PkBytes
        val aeadStart = mlKemCtStart + MlKemCtBytes
        val ephPk = java.util.Arrays.copyOfRange(bytes, ephPkStart, mlKemCtStart)
        val mlKemCt = java.util.Arrays.copyOfRange(bytes, mlKemCtStart, aeadStart)
        val aeadCtTag = java.util.Arrays.copyOfRange(bytes, aeadStart, bytes.length)
        Right((algId, ephPk, mlKemCt, aeadCtTag))
