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

package siida.configchain

import java.security.SecureRandom
import munit.FunSuite
import siida.configchain.api.{ConfigChainError, ConfigEntry}
import siida.crypto.api.PqSignature

final class ConfigEntrySuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  test("encode → decode round-trips a 3-pubkey roster") {
    val pubs = (0 until 3).map(i => PqSignature.generateKeyPair(fixedRng(s"ce-rt-$i"))._2).toVector
    val entry = ConfigEntry(
      epoch = 7L,
      prevHash = Array.fill[Byte](32)(0x11.toByte),
      newRoster = pubs,
      newThreshold = 2,
      extension = "hello".getBytes("UTF-8"),
    )
    val bytes = ConfigEntry.encode(entry)
    val decoded = ConfigEntry.decode(bytes).toOption.get
    assertEquals(decoded.epoch, 7L)
    assertEquals(decoded.prevHash.toSeq, entry.prevHash.toSeq)
    assertEquals(decoded.newThreshold, 2)
    assertEquals(decoded.newRoster.length, 3)
    decoded.newRoster.zip(pubs).foreach { (a, b) =>
      assertEquals(
        PqSignature.serialisePublicKey(a).toSeq,
        PqSignature.serialisePublicKey(b).toSeq)
    }
    assertEquals(decoded.extension.toSeq, "hello".getBytes("UTF-8").toSeq)
  }

  test("decode rejects unknown version byte") {
    val pubs = Vector(PqSignature.generateKeyPair(fixedRng("ce-ver"))._2)
    val bytes = ConfigEntry.encode(ConfigEntry(0L, new Array[Byte](32), pubs, 1, Array.emptyByteArray))
    bytes(0) = 0x42.toByte
    assertEquals(ConfigEntry.decode(bytes), Left(ConfigChainError.UnsupportedVersion))
  }

  test("decode rejects too-short bytes") {
    val tiny = new Array[Byte](10)
    tiny(0) = ConfigEntry.FormatVersion
    val res = ConfigEntry.decode(tiny)
    assert(res.isLeft, s"expected Left, got $res")
  }

  test("encode preserves prev_hash bytes exactly (32 bytes)") {
    val pubs = Vector(PqSignature.generateKeyPair(fixedRng("ce-ph"))._2)
    val ph = Array.tabulate[Byte](32)(i => (i * 7).toByte)
    val bytes = ConfigEntry.encode(ConfigEntry(1L, ph, pubs, 1, Array.emptyByteArray))
    val decoded = ConfigEntry.decode(bytes).toOption.get
    assertEquals(decoded.prevHash.toSeq, ph.toSeq)
  }

  test("empty roster encodes/decodes (chain layer rejects, not codec)") {
    val bytes = ConfigEntry.encode(ConfigEntry(0L, new Array[Byte](32), Vector.empty, 0, Array.emptyByteArray))
    val decoded = ConfigEntry.decode(bytes).toOption.get
    assertEquals(decoded.newRoster.length, 0)
    assertEquals(decoded.newThreshold, 0)
  }
