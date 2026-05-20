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

package siida.pkg.api

import siida.crypto.api.HybridOnion

/** Codec for the inner-plaintext payload of an `AddRequest`
 *  ciphertext. Wire format per
 *  `specs/019-friend-discovery/contracts/wire-format.md`:
 *
 *  ```
 *  2 bytes   sender_identity_length (uint16 BE)
 *  N bytes   sender_identity_bytes
 *  1216      sender_public_bundle (HybridOnion.serialisePublicBundle)
 *  ```
 *
 *  Total: `1218 + sender_identity_length` bytes.
 *
 *  The outer ciphertext (an `AddRequest`) is a HybridOnion
 *  encryption of this payload plus a 1-byte algorithm-ID prefix
 *  (`0x30` per spec 019).
 */
object AddRequestWire:

  private inline val IdentityLenBytes  = 2
  private inline val PublicBundleBytes = 1216
  private inline val FixedOverhead     = IdentityLenBytes + PublicBundleBytes // 1218

  def encode(
    senderIdentity:     Array[Byte],
    senderPublicBundle: HybridOnion.HybridPublicBundle,
  ): Array[Byte] =
    require(senderIdentity.length <= 0xFFFF,
      s"sender_identity too long: ${senderIdentity.length}")
    val pkBytes = HybridOnion.serialisePublicBundle(senderPublicBundle)
    require(pkBytes.length == PublicBundleBytes,
      s"public bundle wire size ${pkBytes.length} != $PublicBundleBytes")
    val total = FixedOverhead + senderIdentity.length
    val out = new Array[Byte](total)
    out(0) = ((senderIdentity.length >>> 8) & 0xFF).toByte
    out(1) = (senderIdentity.length & 0xFF).toByte
    System.arraycopy(senderIdentity, 0, out, IdentityLenBytes, senderIdentity.length)
    System.arraycopy(pkBytes, 0, out, IdentityLenBytes + senderIdentity.length, PublicBundleBytes)
    out

  def decode(bytes: Array[Byte]): Option[(Array[Byte], HybridOnion.HybridPublicBundle)] =
    if bytes.length < FixedOverhead then None
    else
      val identityLen = ((bytes(0) & 0xFF) << 8) | (bytes(1) & 0xFF)
      if bytes.length != FixedOverhead + identityLen then None
      else
        val identity = java.util.Arrays.copyOfRange(bytes, IdentityLenBytes, IdentityLenBytes + identityLen)
        val pkOffset = IdentityLenBytes + identityLen
        val pkBytes = java.util.Arrays.copyOfRange(bytes, pkOffset, pkOffset + PublicBundleBytes)
        HybridOnion.deserialisePublicBundle(pkBytes) match
          case Right(pk) => Some((identity, pk))
          case Left(_)   => None
