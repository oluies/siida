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

package siida.configchain.api

import siida.crypto.api.PqSignature

/** Decoded view of a config-chain entry payload (spec 006).
 *
 *  Wire layout (FormatVersion 0x01):
 *
 *  ```
 *  offset                size                          field
 *  0                     1                              FormatVersion (0x01)
 *  1                     8                              epoch (uint64 BE)
 *  9                     32                             prev_hash (SHA3-256)
 *  41                    2                              new_roster size `n` (uint16 BE)
 *  43                    n × 1953                       new_roster pubkeys (PqSignature wire envelopes)
 *  43 + n×1953           2                              new_threshold (uint16 BE)
 *  45 + n×1953           variable                       extension bytes (opaque to 006)
 *  ```
 */
final case class ConfigEntry(
  epoch:        Long,
  prevHash:     Array[Byte],          // 32 bytes; all-zero for genesis
  newRoster:    Vector[PqSignature.PqPublicKey],
  newThreshold: Int,
  extension:    Array[Byte],
)

object ConfigEntry:

  val FormatVersion: Byte = 0x01

  val PrevHashBytes: Int = 32

  /** PqSignature public-key wire envelope size (spec 013). */
  inline val PubKeyWireBytes = 1953

  inline private val EpochBytes        = 8
  inline private val NRosterBytes      = 2
  inline private val NThresholdBytes   = 2
  inline private val FixedPrelude      = 1 + EpochBytes + 32 + NRosterBytes
  inline private val FixedTail         = NThresholdBytes

  val GenesisPrevHash: Array[Byte] = new Array[Byte](PrevHashBytes)

  def encode(entry: ConfigEntry): Array[Byte] =
    require(entry.prevHash.length == PrevHashBytes,
      s"prev_hash must be exactly $PrevHashBytes bytes")
    val n = entry.newRoster.length
    val total = FixedPrelude + n * PubKeyWireBytes + FixedTail + entry.extension.length
    val out = new Array[Byte](total)
    var off = 0
    out(off) = FormatVersion; off += 1
    writeLongBE(out, off, entry.epoch); off += EpochBytes
    System.arraycopy(entry.prevHash, 0, out, off, PrevHashBytes); off += PrevHashBytes
    writeUInt16BE(out, off, n); off += NRosterBytes
    entry.newRoster.foreach { pk =>
      val pkBytes = PqSignature.serialisePublicKey(pk)
      System.arraycopy(pkBytes, 0, out, off, PubKeyWireBytes)
      off += PubKeyWireBytes
    }
    writeUInt16BE(out, off, entry.newThreshold); off += NThresholdBytes
    System.arraycopy(entry.extension, 0, out, off, entry.extension.length)
    out

  def decode(bytes: Array[Byte]): Either[ConfigChainError, ConfigEntry] =
    if bytes.length < FixedPrelude + FixedTail then
      Left(ConfigChainError.MalformedEntry(s"payload too short: ${bytes.length}"))
    else if bytes(0) != FormatVersion then
      Left(ConfigChainError.UnsupportedVersion)
    else
      var off = 1
      val epoch = readLongBE(bytes, off); off += EpochBytes
      val prev = java.util.Arrays.copyOfRange(bytes, off, off + PrevHashBytes); off += PrevHashBytes
      val n = readUInt16BE(bytes, off); off += NRosterBytes
      val expectedRosterEnd = off + n * PubKeyWireBytes
      if bytes.length < expectedRosterEnd + NThresholdBytes then
        Left(ConfigChainError.MalformedEntry("payload shorter than declared roster"))
      else
        val rosterEither = (0 until n).foldLeft(
          Right(Vector.newBuilder[PqSignature.PqPublicKey])
            : Either[ConfigChainError, scala.collection.mutable.Builder[PqSignature.PqPublicKey, Vector[PqSignature.PqPublicKey]]],
        ) { (acc, _) =>
          acc.flatMap { b =>
            val start = off
            off += PubKeyWireBytes
            val slice = java.util.Arrays.copyOfRange(bytes, start, start + PubKeyWireBytes)
            PqSignature.deserialisePublicKey(slice).left.map { _ =>
              ConfigChainError.MalformedEntry("roster pubkey deserialisation failed")
            }.map { pk => b += pk; b }
          }
        }
        rosterEither.map { rosterBuilder =>
          val threshold = readUInt16BE(bytes, off); off += NThresholdBytes
          val ext = java.util.Arrays.copyOfRange(bytes, off, bytes.length)
          ConfigEntry(epoch, prev, rosterBuilder.result(), threshold, ext)
        }

  private def writeLongBE(out: Array[Byte], off: Int, v: Long): Unit =
    var i = 0
    while i < 8 do
      out(off + i) = ((v >>> (56 - i * 8)) & 0xFF).toByte
      i += 1

  private def readLongBE(in: Array[Byte], off: Int): Long =
    var v = 0L
    var i = 0
    while i < 8 do
      v = (v << 8) | (in(off + i) & 0xFFL)
      i += 1
    v

  private def writeUInt16BE(out: Array[Byte], off: Int, v: Int): Unit =
    out(off) = ((v >>> 8) & 0xFF).toByte
    out(off + 1) = (v & 0xFF).toByte

  private def readUInt16BE(in: Array[Byte], off: Int): Int =
    ((in(off) & 0xFF) << 8) | (in(off + 1) & 0xFF)
