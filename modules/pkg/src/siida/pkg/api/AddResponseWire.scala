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

/** Codec for the inner-plaintext payload of an `AddResponse`
 *  ciphertext (spec 020). Wire format:
 *
 *  ```
 *  2 bytes   sender_identity_length (uint16 BE)
 *  N bytes   sender_identity_bytes
 *  2 bytes   ack_payload_length (uint16 BE)
 *  M bytes   ack_payload_bytes
 *  ```
 *
 *  Total: `4 + N + M` bytes.
 *
 *  The outer ciphertext (an `AddResponse`) is a HybridOnion
 *  encryption of this payload plus a 1-byte algorithm-ID prefix
 *  (`0x31`).
 */
object AddResponseWire:

  private inline val IdentityLenBytes = 2
  private inline val AckLenBytes      = 2
  private inline val FixedOverhead    = IdentityLenBytes + AckLenBytes

  def encode(
    senderIdentity: Array[Byte],
    ackPayload:     Array[Byte],
  ): Array[Byte] =
    require(senderIdentity.length <= 0xFFFF,
      s"sender_identity too long: ${senderIdentity.length}")
    require(ackPayload.length <= 0xFFFF,
      s"ack_payload too long: ${ackPayload.length}")
    val total = FixedOverhead + senderIdentity.length + ackPayload.length
    val out = new Array[Byte](total)
    var off = 0
    out(off) = ((senderIdentity.length >>> 8) & 0xFF).toByte; off += 1
    out(off) = (senderIdentity.length & 0xFF).toByte;         off += 1
    System.arraycopy(senderIdentity, 0, out, off, senderIdentity.length)
    off += senderIdentity.length
    out(off) = ((ackPayload.length >>> 8) & 0xFF).toByte;     off += 1
    out(off) = (ackPayload.length & 0xFF).toByte;             off += 1
    System.arraycopy(ackPayload, 0, out, off, ackPayload.length)
    out

  def decode(bytes: Array[Byte]): Option[(Array[Byte], Array[Byte])] =
    if bytes.length < FixedOverhead then None
    else
      val identityLen = ((bytes(0) & 0xFF) << 8) | (bytes(1) & 0xFF)
      val ackLenStart = IdentityLenBytes + identityLen
      if bytes.length < ackLenStart + AckLenBytes then None
      else
        val ackLen = ((bytes(ackLenStart) & 0xFF) << 8) | (bytes(ackLenStart + 1) & 0xFF)
        val expectedTotal = FixedOverhead + identityLen + ackLen
        if bytes.length != expectedTotal then None
        else
          val identity = java.util.Arrays.copyOfRange(bytes, IdentityLenBytes, IdentityLenBytes + identityLen)
          val ackOff   = ackLenStart + AckLenBytes
          val ack      = java.util.Arrays.copyOfRange(bytes, ackOff, ackOff + ackLen)
          Some((identity, ack))
