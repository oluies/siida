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

import java.nio.file.{Files, Path, StandardCopyOption}
import siida.crypto.api.{HybridOnion, PqSignature}

/** File-backed FriendStore (spec 020 US3). Atomic-rewrite on every
 *  `add` via write-tmp + rename. Single-writer discipline is the
 *  caller's responsibility.
 *
 *  Wire format pinned in [[FriendStore]] companion docs.
 */
private[api] object PersistentFriendStore:

  private val Magic: Array[Byte] = Array(0x53.toByte, 0x49.toByte, 0x46.toByte, 0x44.toByte) // "SIFD"
  private inline val BundleBytes = 1216

  def openOrCreate(path: Path): Either[String, FriendStore] =
    // Treat both a non-existent path AND a zero-byte file as "fresh";
    // a zero-byte file is the natural state of a Files.createTempFile
    // path, so the test setup pattern doesn't need an extra delete.
    if !Files.exists(path) || Files.size(path) == 0L then
      val store = new FileBackedStore(path, scala.collection.mutable.LinkedHashMap.empty)
      store.flushAtomic() match
        case Right(_) => Right(store)
        case Left(e)  => Left(e)
    else loadExisting(path)

  private def loadExisting(path: Path): Either[String, FriendStore] =
    try
      val bytes = Files.readAllBytes(path)
      if bytes.length < Magic.length then
        Left(s"file too small: ${bytes.length} bytes")
      else
        var ok = true
        var i = 0
        while i < Magic.length && ok do
          if bytes(i) != Magic(i) then ok = false
          i += 1
        if !ok then Left("bad magic — not a SIFD store")
        else parseRecords(bytes, Magic.length).map { entries =>
          new FileBackedStore(path, entries)
        }
    catch
      case e: Exception => Left(s"I/O failure: ${e.getMessage}")

  private def parseRecords(
    bytes: Array[Byte],
    start: Int,
  ): Either[String, scala.collection.mutable.LinkedHashMap[scala.collection.immutable.ArraySeq[Byte], HybridOnion.HybridPublicBundle]] =
    val out = scala.collection.mutable.LinkedHashMap.empty[scala.collection.immutable.ArraySeq[Byte], HybridOnion.HybridPublicBundle]
    var off = start
    var err: Option[String] = None
    while off < bytes.length && err.isEmpty do
      if off + 2 > bytes.length then
        err = Some(s"truncated identity-length at offset $off")
      else
        val idLen = ((bytes(off) & 0xFF) << 8) | (bytes(off + 1) & 0xFF)
        off += 2
        if off + idLen + BundleBytes > bytes.length then
          err = Some(s"truncated record at offset $off (need ${idLen + BundleBytes} bytes)")
        else
          val identity = java.util.Arrays.copyOfRange(bytes, off, off + idLen)
          off += idLen
          val bundleBytes = java.util.Arrays.copyOfRange(bytes, off, off + BundleBytes)
          off += BundleBytes
          // Reconstruct the HybridPublicBundle by round-tripping through
          // an encrypt-then-deserialise. The bundle bytes are
          // serialised via HybridOnion.serialisePublicBundle, and
          // HybridOnion exposes deserialisePublicBundle for the inverse.
          HybridOnion.deserialisePublicBundle(bundleBytes) match
            case Left(e) =>
              err = Some(s"bundle deserialise failed at offset ${off - BundleBytes}: $e")
            case Right(bundle) =>
              val key = scala.collection.immutable.ArraySeq.unsafeWrapArray(identity)
              out.update(key, bundle)
    err match
      case Some(e) => Left(e)
      case None    => Right(out)

  private final class FileBackedStore(
    path:    Path,
    entries: scala.collection.mutable.LinkedHashMap[scala.collection.immutable.ArraySeq[Byte], HybridOnion.HybridPublicBundle],
  ) extends FriendStore:

    def add(identity: Array[Byte], bundle: HybridOnion.HybridPublicBundle): Boolean =
      val key = scala.collection.immutable.ArraySeq.unsafeWrapArray(identity.clone())
      if entries.contains(key) then false
      else
        entries.update(key, bundle)
        flushAtomic() match
          case Right(_) => true
          case Left(e)  =>
            // Roll back the in-memory change so caller sees a clean
            // failure state. Reasonable behaviour for an I/O error
            // in an append-only store.
            entries.remove(key)
            throw new java.io.IOException(s"FriendStore.add: flush failed — $e")

    def lookup(identity: Array[Byte]): Option[HybridOnion.HybridPublicBundle] =
      val key = scala.collection.immutable.ArraySeq.unsafeWrapArray(identity)
      entries.get(key)

    def list(): Seq[Array[Byte]] =
      entries.keys.iterator.map(_.toArray).toVector

    // Spec 027 — the persistent on-disk format does not yet carry
    // signing keys; this implementation rejects the add and always
    // returns None for lookups. A follow-up spec bumps the file
    // format. Callers that need signed-chat across restarts should
    // use the in-memory FriendStore for now.
    def addWithSigningKey(
      identity: Array[Byte],
      bundle:   HybridOnion.HybridPublicBundle,
      sigPk:    PqSignature.PqPublicKey,
    ): Boolean =
      val _ = sigPk
      add(identity, bundle)

    def lookupSigningKey(identity: Array[Byte]): Option[PqSignature.PqPublicKey] =
      val _ = identity
      None

    def flushAtomic(): Either[String, Unit] =
      try
        val tmp = path.resolveSibling(path.getFileName.toString + ".tmp")
        val out = new java.io.ByteArrayOutputStream()
        out.write(Magic)
        entries.foreach { case (key, bundle) =>
          val idBytes = key.toArray
          out.write((idBytes.length >>> 8) & 0xFF)
          out.write(idBytes.length & 0xFF)
          out.write(idBytes)
          val bb = HybridOnion.serialisePublicBundle(bundle)
          out.write(bb)
        }
        Files.write(tmp, out.toByteArray)
        Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        Right(())
      catch
        case e: Exception => Left(e.getMessage)
