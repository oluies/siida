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

/** Codec for the directory-entry payload that the PKG roster
 *  signs over (FR-006). Wire format per
 *  `specs/005-pkg-keybootstrap/contracts/wire-format.md`:
 *
 *  ```
 *  2 bytes   identity_length (uint16 BE)
 *  N bytes   identity_bytes
 *  8 bytes   mailbox_id (uint64 BE)
 *  1216      public_bundle_wire_bytes (HybridOnion.serialisePublicBundle)
 *  ```
 *
 *  Total: `1226 + identity_length` bytes.
 *
 *  Consumers (notably spec 015's `Directory.inMemory`) read this
 *  payload back to recover the public bundle for encryption.
 */
object DirectoryEntryWire:

  private inline val IdentityLenBytes  = 2
  private inline val MailboxIdBytes    = 8
  private inline val PublicBundleBytes = 1216 // spec 012's wire size
  private inline val FixedOverhead     = IdentityLenBytes + MailboxIdBytes + PublicBundleBytes // 1226

  /** Encode an identity binding into the payload bytes that the
   *  PKG roster signs over.
   */
  def encode(
    identity:     Array[Byte],
    mailboxId:    Long,
    publicBundle: HybridOnion.HybridPublicBundle,
  ): Array[Byte] =
    require(identity.length <= 0xFFFF,
      s"identity too long: ${identity.length}")
    val pkBytes = HybridOnion.serialisePublicBundle(publicBundle)
    require(pkBytes.length == PublicBundleBytes,
      s"public bundle wire size ${pkBytes.length} != $PublicBundleBytes")
    val total = FixedOverhead + identity.length
    val out = new Array[Byte](total)
    // identity_length
    out(0) = ((identity.length >>> 8) & 0xFF).toByte
    out(1) = (identity.length & 0xFF).toByte
    // identity_bytes
    System.arraycopy(identity, 0, out, IdentityLenBytes, identity.length)
    // mailbox_id (big-endian)
    val midOff = IdentityLenBytes + identity.length
    var i = 0
    while i < MailboxIdBytes do
      out(midOff + i) = ((mailboxId >>> ((MailboxIdBytes - 1 - i) * 8)) & 0xFF).toByte
      i += 1
    // public bundle bytes
    System.arraycopy(pkBytes, 0, out, midOff + MailboxIdBytes, PublicBundleBytes)
    out

  /** Decode the payload bytes back into the (identity, mailboxId,
   *  publicBundle) triple. Used by `Directory.inMemory` consumers
   *  but exposed here for cross-spec coordination + tests.
   */
  def decode(bytes: Array[Byte]): Option[(Array[Byte], Long, HybridOnion.HybridPublicBundle)] =
    if bytes.length < FixedOverhead then None
    else
      val identityLen = ((bytes(0) & 0xFF) << 8) | (bytes(1) & 0xFF)
      if bytes.length != FixedOverhead + identityLen then None
      else
        val identity = java.util.Arrays.copyOfRange(bytes, IdentityLenBytes, IdentityLenBytes + identityLen)
        val midOff = IdentityLenBytes + identityLen
        var mid: Long = 0L
        var i = 0
        while i < MailboxIdBytes do
          mid = (mid << 8) | (bytes(midOff + i).toLong & 0xFFL)
          i += 1
        val pkBytes = java.util.Arrays.copyOfRange(bytes,
          midOff + MailboxIdBytes,
          midOff + MailboxIdBytes + PublicBundleBytes)
        HybridOnion.deserialisePublicBundle(pkBytes) match
          case Right(pk) => Some((identity, mid, pk))
          case Left(_)   => None
