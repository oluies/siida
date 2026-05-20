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

/** Inner SDK envelope sitting INSIDE `MailboxEnvelope.payload` after
 *  the mix chain peels its onion layers. The 1-byte SDK type byte
 *  discriminates between chat-message payloads and friendship
 *  add-requests so the recipient SDK can route them.
 *
 *  Format:
 *  ```
 *  offset  size  field
 *  0       1     SDK type byte (0x01 chat, 0x02 add-request)
 *  1       *     inner payload (opaque to this codec; type-specific)
 *  ```
 *
 *  The inner payload's interpretation:
 *  - `0x01 chat`     : a serialised `HybridOnion.OnionLayer` (e2e
 *                       encrypted to the recipient's bundle)
 *  - `0x02 add-req`  : a serialised `Friendship.AddRequest`
 *                       (the AddRequest itself is e2e-encrypted to
 *                       the recipient's bundle via HybridOnion under
 *                       the hood)
 */
object SdkEnvelope:

  object Type:
    val ChatMessage: Byte = 0x01.toByte
    val AddRequest:  Byte = 0x02.toByte

  def wrap(typ: Byte, inner: Array[Byte]): Array[Byte] =
    val out = new Array[Byte](1 + inner.length)
    out(0) = typ
    System.arraycopy(inner, 0, out, 1, inner.length)
    out

  def parse(bytes: Array[Byte]): Either[SdkError, (Byte, Array[Byte])] =
    if bytes.length < 1 then
      Left(SdkError.MalformedEnvelope("empty SDK envelope"))
    else
      val typ   = bytes(0)
      val inner = java.util.Arrays.copyOfRange(bytes, 1, bytes.length)
      Right((typ, inner))
