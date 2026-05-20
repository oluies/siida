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

package siida.agent.api

/** Agent-messaging convention envelope (spec 008).
 *
 *  Sits INSIDE an SDK-level `ChatMessage` payload (type 0x01). The
 *  4-byte `SIAG` magic distinguishes agent traffic from raw chat;
 *  a non-agent peer's payload is recognised by decode-failure +
 *  surfaced as `RawChat`.
 *
 *  Wire format:
 *  ```
 *  offset  size  field
 *  0       4     magic "SIAG"
 *  4       1     kind (0x01 Request, 0x02 Response, 0x03 Notification)
 *  5       16    request_id (UUID; 16 × 0x00 for Notification)
 *  21      2     content_length (uint16 BE)
 *  23      *     content bytes
 *  ```
 */
object AgentEnvelope:

  val Magic: Array[Byte] = Array(0x53.toByte, 0x49.toByte, 0x41.toByte, 0x47.toByte) // "SIAG"

  object Kind:
    val Request:      Byte = 0x01.toByte
    val Response:     Byte = 0x02.toByte
    val Notification: Byte = 0x03.toByte

  inline val RequestIdBytes  = 16
  inline val MagicBytes      = 4
  inline val KindBytes       = 1
  inline val ContentLenBytes = 2
  inline val Prelude         = MagicBytes + KindBytes + RequestIdBytes + ContentLenBytes // 23

  final case class Decoded(
    kind:      Byte,
    requestId: Array[Byte], // length 16
    content:   Array[Byte],
  )

  val ZeroRequestId: Array[Byte] = new Array[Byte](RequestIdBytes)

  def encode(kind: Byte, requestId: Array[Byte], content: Array[Byte]): Array[Byte] =
    require(requestId.length == RequestIdBytes,
      s"requestId must be exactly $RequestIdBytes bytes, got ${requestId.length}")
    require(content.length <= 0xFFFF,
      s"content too long: ${content.length}")
    val out = new Array[Byte](Prelude + content.length)
    System.arraycopy(Magic, 0, out, 0, MagicBytes)
    out(MagicBytes) = kind
    System.arraycopy(requestId, 0, out, MagicBytes + KindBytes, RequestIdBytes)
    val lenOff = MagicBytes + KindBytes + RequestIdBytes
    out(lenOff)     = ((content.length >>> 8) & 0xFF).toByte
    out(lenOff + 1) = (content.length & 0xFF).toByte
    System.arraycopy(content, 0, out, Prelude, content.length)
    out

  /** Try to decode as an agent envelope. Returns `None` on any
   *  failure (bad magic, short input, length mismatch); the caller
   *  treats `None` as "raw chat".
   */
  def decode(bytes: Array[Byte]): Option[Decoded] =
    if bytes.length < Prelude then None
    else
      // Check magic
      var i = 0
      var magicOk = true
      while i < MagicBytes && magicOk do
        if bytes(i) != Magic(i) then magicOk = false
        i += 1
      if !magicOk then None
      else
        val kind = bytes(MagicBytes)
        val rid  = java.util.Arrays.copyOfRange(bytes, MagicBytes + KindBytes, MagicBytes + KindBytes + RequestIdBytes)
        val lenOff = MagicBytes + KindBytes + RequestIdBytes
        val contentLen = ((bytes(lenOff) & 0xFF) << 8) | (bytes(lenOff + 1) & 0xFF)
        if bytes.length != Prelude + contentLen then None
        else
          val content = java.util.Arrays.copyOfRange(bytes, Prelude, Prelude + contentLen)
          Some(Decoded(kind, rid, content))
