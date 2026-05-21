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

package siida.sdk.api

/** Inner-payload codec for an authenticated chat (spec 023, SDK
 *  type byte `0x03`). Lives INSIDE the e2e-encrypted layer
 *  produced by HybridOnion.encrypt to the recipient's bundle.
 *
 *  Wire format:
 *  ```
 *  offset  size  field
 *  0       2     sender_identity_length (uint16 BE)
 *  2       N     sender_identity_bytes
 *  2+N     *     chat_payload_bytes (opaque)
 *  ```
 */
object AuthenticatedChatWire:

  private inline val IdLenBytes = 2

  def encode(senderIdentity: Array[Byte], payload: Array[Byte]): Array[Byte] =
    require(senderIdentity.length <= 0xFFFF,
      s"sender_identity too long: ${senderIdentity.length}")
    val out = new Array[Byte](IdLenBytes + senderIdentity.length + payload.length)
    out(0) = ((senderIdentity.length >>> 8) & 0xFF).toByte
    out(1) = (senderIdentity.length & 0xFF).toByte
    System.arraycopy(senderIdentity, 0, out, IdLenBytes, senderIdentity.length)
    System.arraycopy(payload, 0, out, IdLenBytes + senderIdentity.length, payload.length)
    out

  def decode(bytes: Array[Byte]): Either[SdkError, (Array[Byte], Array[Byte])] =
    if bytes.length < IdLenBytes then
      Left(SdkError.MalformedEnvelope("authenticated-chat: input shorter than length prefix"))
    else
      val idLen = ((bytes(0) & 0xFF) << 8) | (bytes(1) & 0xFF)
      if idLen == 0 then
        Left(SdkError.MalformedEnvelope("authenticated-chat: empty sender identity"))
      else if bytes.length < IdLenBytes + idLen then
        Left(SdkError.MalformedEnvelope("authenticated-chat: declared sender_id_len exceeds input"))
      else
        val id      = java.util.Arrays.copyOfRange(bytes, IdLenBytes, IdLenBytes + idLen)
        val payload = java.util.Arrays.copyOfRange(bytes, IdLenBytes + idLen, bytes.length)
        Right((id, payload))
