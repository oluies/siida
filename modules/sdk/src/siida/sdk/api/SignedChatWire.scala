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

/** Inner-payload codec for a signed chat (spec 027, SDK type byte
 *  `0x04`). Lives INSIDE the e2e-encrypted layer produced by
 *  HybridOnion.encrypt to the recipient's bundle.
 *
 *  Wire format:
 *  ```
 *  offset      size       field
 *  0           2          sender_identity_length (uint16 BE)
 *  2           N          sender_identity_bytes
 *  2+N         2          signature_length (uint16 BE; expected 3310)
 *  4+N         S          signature_bytes (ML-DSA-65)
 *  4+N+S       *          chat_payload_bytes
 *  ```
 *
 *  The signed bytes (input to PqSignature.sign / verify) are
 *  constructed by [[signedMessage]] below — they include the SDK
 *  type byte 0x04, the sender identity, the RECIPIENT identity, and
 *  the chat payload. The recipient identity is NOT on the wire (the
 *  verifier supplies its own identity).
 */
object SignedChatWire:

  private inline val LenBytes = 2

  /** The byte string that gets signed / verified. Binds the SDK
   *  type, both endpoint identities, and the chat content so that
   *  a signature for one (sender, recipient, payload) tuple cannot
   *  be replayed across recipients or envelope types.
   */
  def signedMessage(
    senderId:    Array[Byte],
    recipientId: Array[Byte],
    payload:     Array[Byte],
  ): Array[Byte] =
    val out = new Array[Byte](1 + LenBytes + senderId.length + LenBytes + recipientId.length + payload.length)
    var off = 0
    out(off) = SdkEnvelope.Type.SignedChat; off += 1
    out(off) = ((senderId.length >>> 8) & 0xFF).toByte; off += 1
    out(off) = (senderId.length & 0xFF).toByte;        off += 1
    System.arraycopy(senderId, 0, out, off, senderId.length); off += senderId.length
    out(off) = ((recipientId.length >>> 8) & 0xFF).toByte; off += 1
    out(off) = (recipientId.length & 0xFF).toByte;        off += 1
    System.arraycopy(recipientId, 0, out, off, recipientId.length); off += recipientId.length
    System.arraycopy(payload, 0, out, off, payload.length)
    out

  def encode(
    senderIdentity: Array[Byte],
    signature:      Array[Byte],
    payload:        Array[Byte],
  ): Array[Byte] =
    require(senderIdentity.length <= 0xFFFF,
      s"sender_identity too long: ${senderIdentity.length}")
    require(signature.length <= 0xFFFF,
      s"signature too long: ${signature.length}")
    val out = new Array[Byte](LenBytes + senderIdentity.length + LenBytes + signature.length + payload.length)
    var off = 0
    out(off) = ((senderIdentity.length >>> 8) & 0xFF).toByte; off += 1
    out(off) = (senderIdentity.length & 0xFF).toByte;        off += 1
    System.arraycopy(senderIdentity, 0, out, off, senderIdentity.length); off += senderIdentity.length
    out(off) = ((signature.length >>> 8) & 0xFF).toByte; off += 1
    out(off) = (signature.length & 0xFF).toByte;        off += 1
    System.arraycopy(signature, 0, out, off, signature.length); off += signature.length
    System.arraycopy(payload, 0, out, off, payload.length)
    out

  def decode(bytes: Array[Byte]): Either[SdkError, (Array[Byte], Array[Byte], Array[Byte])] =
    if bytes.length < LenBytes then
      Left(SdkError.MalformedEnvelope("signed-chat: input shorter than sender-id length prefix"))
    else
      val idLen = ((bytes(0) & 0xFF) << 8) | (bytes(1) & 0xFF)
      if idLen == 0 then
        Left(SdkError.MalformedEnvelope("signed-chat: empty sender identity"))
      else if bytes.length < LenBytes + idLen + LenBytes then
        Left(SdkError.MalformedEnvelope("signed-chat: declared sender_id_len exceeds input"))
      else
        val idEnd  = LenBytes + idLen
        val sigLen = ((bytes(idEnd) & 0xFF) << 8) | (bytes(idEnd + 1) & 0xFF)
        if sigLen == 0 then
          Left(SdkError.MalformedEnvelope("signed-chat: empty signature"))
        else if bytes.length < idEnd + LenBytes + sigLen then
          Left(SdkError.MalformedEnvelope("signed-chat: declared sig_len exceeds input"))
        else
          val id      = java.util.Arrays.copyOfRange(bytes, LenBytes, idEnd)
          val sig     = java.util.Arrays.copyOfRange(bytes, idEnd + LenBytes, idEnd + LenBytes + sigLen)
          val payload = java.util.Arrays.copyOfRange(bytes, idEnd + LenBytes + sigLen, bytes.length)
          Right((id, sig, payload))
