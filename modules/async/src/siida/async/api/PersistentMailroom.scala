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

package siida.async.api

import java.nio.file.{Files, Path, StandardCopyOption}
import siida.mixnet.api.MixChain

/** File-backed [[Mailroom]] (spec 009 US3). Atomic write-tmp + rename
 *  on every state-changing operation. Single-writer discipline.
 *
 *  Wire format (version 0x01):
 *  ```
 *  4B  magic "SIMR"
 *  1B  version (0x01)
 *  N × per-record:
 *    8B  deposit_time_ms (int64 BE)
 *    4B  envelope_length (int32 BE)
 *    *   envelope_bytes (MixChain.serialiseEnvelope output)
 *  ```
 */
private[api] object PersistentMailroom:

  private val Magic: Array[Byte] = Array(0x53.toByte, 0x49.toByte, 0x4D.toByte, 0x52.toByte) // "SIMR"
  private val Version: Byte = 0x01.toByte

  def openOrCreate(path: Path, ttlMs: Long): Either[String, Mailroom] =
    if !Files.exists(path) || Files.size(path) == 0L then
      val store = new FileBackedMailroom(path, ttlMs)
      store.flush() match
        case Right(_) => Right(store)
        case Left(e)  => Left(e)
    else loadExisting(path, ttlMs)

  private def loadExisting(path: Path, ttlMs: Long): Either[String, Mailroom] =
    try
      val bytes = Files.readAllBytes(path)
      if bytes.length < 5 then Left("truncated header")
      else
        var ok = true
        var i = 0
        while i < Magic.length && ok do
          if bytes(i) != Magic(i) then ok = false
          i += 1
        if !ok then Left("bad magic — not a SIMR store")
        else if bytes(4) != Version then Left(s"unsupported version: ${bytes(4)}")
        else parseRecords(bytes, 5).map { slots =>
          new FileBackedMailroom(path, ttlMs, slots)
        }
    catch
      case e: Exception => Left(s"I/O failure: ${e.getMessage}")

  private def parseRecords(
    bytes: Array[Byte],
    start: Int,
  ): Either[String, scala.collection.mutable.ArrayBuffer[Mailroom.Slot]] =
    val out = scala.collection.mutable.ArrayBuffer.empty[Mailroom.Slot]
    var off = start
    var err: Option[String] = None
    while off < bytes.length && err.isEmpty do
      if off + 12 > bytes.length then
        err = Some(s"truncated record header at offset $off")
      else
        val depositMs = readLongBE(bytes, off); off += 8
        val envLen    = readIntBE(bytes, off);  off += 4
        if envLen < 0 || off + envLen > bytes.length then
          err = Some(s"bad envelope length $envLen at offset $off")
        else
          val envBytes = java.util.Arrays.copyOfRange(bytes, off, off + envLen)
          off += envLen
          MixChain.deserialiseEnvelope(envBytes) match
            case Right(env) => out += Mailroom.Slot(env, depositMs)
            case Left(e)    => err = Some(s"envelope deserialise failed: $e")
    err match
      case Some(e) => Left(e)
      case None    => Right(out)

  private def readLongBE(in: Array[Byte], off: Int): Long =
    var v = 0L
    var i = 0
    while i < 8 do
      v = (v << 8) | (in(off + i) & 0xFFL)
      i += 1
    v

  private def readIntBE(in: Array[Byte], off: Int): Int =
    var v = 0
    var i = 0
    while i < 4 do
      v = (v << 8) | (in(off + i) & 0xFF)
      i += 1
    v

  private final class FileBackedMailroom(
    path:  Path,
    ttlMs: Long,
    seed:  scala.collection.mutable.ArrayBuffer[Mailroom.Slot] = scala.collection.mutable.ArrayBuffer.empty,
  ) extends Mailroom:

    private val all = seed

    def deposit(env: MixChain.MailboxEnvelope, nowMs: Long): Boolean =
      val id = MixChain.envelopeMailboxId(env)
      if id == MixChain.CoverMailboxId || id == MixChain.BroadcastMailboxId then false
      else
        all += Mailroom.Slot(env, nowMs)
        flush() match
          case Right(_) => true
          case Left(e)  =>
            all.dropRightInPlace(1)
            throw new java.io.IOException(s"Mailroom.deposit: flush failed — $e")

    def retrieve(mailboxId: Long, nowMs: Long): Seq[MixChain.MailboxEnvelope] =
      val expiry = nowMs - ttlMs
      val (matching, others) = all.partition(s => MixChain.envelopeMailboxId(s.env) == mailboxId)
      val live = matching.filter(_.depositMs >= expiry)
      all.clear()
      all ++= others
      flush() match
        case Right(_) => live.iterator.map(_.env).toVector
        case Left(e)  =>
          all ++= matching
          throw new java.io.IOException(s"Mailroom.retrieve: flush failed — $e")

    def size: Int = all.length

    def flush(): Either[String, Unit] =
      try
        val tmp = path.resolveSibling(path.getFileName.toString + ".tmp")
        val out = new java.io.ByteArrayOutputStream()
        out.write(Magic)
        out.write(Version.toInt)
        all.foreach { slot =>
          writeLongBE(out, slot.depositMs)
          val env = MixChain.serialiseEnvelope(slot.env)
          writeIntBE(out, env.length)
          out.write(env)
        }
        Files.write(tmp, out.toByteArray)
        Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        Right(())
      catch
        case e: Exception => Left(e.getMessage)

    private def writeLongBE(out: java.io.ByteArrayOutputStream, v: Long): Unit =
      var i = 0
      while i < 8 do
        out.write(((v >>> (56 - i * 8)) & 0xFF).toInt)
        i += 1

    private def writeIntBE(out: java.io.ByteArrayOutputStream, v: Int): Unit =
      out.write((v >>> 24) & 0xFF)
      out.write((v >>> 16) & 0xFF)
      out.write((v >>> 8) & 0xFF)
      out.write(v & 0xFF)

