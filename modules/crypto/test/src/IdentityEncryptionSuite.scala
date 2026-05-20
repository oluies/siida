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

package siida.crypto.api

import java.security.SecureRandom
import munit.FunSuite

/** Spec 015 — IdentityEncryption: PKG-directory + HybridOnion. */
final class IdentityEncryptionSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private val pkgDst = "siida/test/v1/pkg-directory".getBytes("UTF-8")

  /** Build a tiny PKG roster of N signers + a directory with one
   *  signed entry per (identity, recipient-bundle) pair.
   */
  private case class Fixture(
    rosterSks: Seq[PqSignature.PqPrivateKey],
    rosterPks: Seq[PqSignature.PqPublicKey],
    directory: Directory,
    recipients: Map[String, (HybridOnion.HybridSecretBundle, HybridOnion.HybridPublicBundle)],
  )

  private def buildFixture(
    identities: Seq[String],
    rosterSize: Int = 3,
    threshold:  Int = 2,
  ): Fixture =
    val rosterPairs = (0 until rosterSize).map(i =>
      PqSignature.generateKeyPair(fixedRng(s"pkg-roster-$i")))
    val rosterSks = rosterPairs.map(_._1)
    val rosterPks = rosterPairs.map(_._2)

    // Per identity: a hybrid bundle + a MultiSignedEntry signed by
    // roster signers 0..(threshold-1) attesting the binding.
    val perId = identities.map { id =>
      val (secret, public) = HybridOnion.generateBundle(fixedRng(s"recipient-$id"))
      val payload = HybridOnion.serialisePublicBundle(public)
      val msg = MultiSignedEntry.signedMessage(payload, pkgDst)
      val sigs = (0 until threshold).map(i => (i, PqSignature.sign(rosterSks(i), msg)))
      val entry = MultiSignedEntry.assemble(payload, sigs).toOption.get
      val idBytes = id.getBytes("UTF-8")
      val key: IArray[Byte] = IArray.unsafeFromArray(idBytes)
      (id -> (secret, public), key -> (public, entry))
    }
    val recipients = perId.map(_._1).toMap
    val entries    = perId.map(_._2).toMap

    val directory = Directory.inMemory(entries, rosterPks, threshold, pkgDst)
    Fixture(rosterSks, rosterPks, directory, recipients)

  // ── Happy path ─────────────────────────────────────────────────

  test("end-to-end: encrypt to alice via directory, alice decrypts") {
    val f = buildFixture(Seq("alice@siida"))
    val (aliceSecret, _) = f.recipients("alice@siida")

    val ct = IdentityEncryption.encrypt(
      f.directory,
      "alice@siida".getBytes("UTF-8"),
      "hello alice".getBytes("UTF-8"),
      fixedRng("encrypt-1"),
    ).toOption.get

    val plain = IdentityEncryption.decrypt(aliceSecret, ct).toOption.get
    assertEquals(plain.toSeq, "hello alice".getBytes("UTF-8").toSeq)
  }

  test("end-to-end: 3-identity directory routes the right ciphertext to bob") {
    val f = buildFixture(Seq("alice@siida", "bob@siida", "carol@siida"))
    val (bobSecret, _) = f.recipients("bob@siida")
    val ct = IdentityEncryption.encrypt(
      f.directory,
      "bob@siida".getBytes("UTF-8"),
      "msg for bob".getBytes("UTF-8"),
      fixedRng("encrypt-2"),
    ).toOption.get
    val plain = IdentityEncryption.decrypt(bobSecret, ct).toOption.get
    assertEquals(plain.toSeq, "msg for bob".getBytes("UTF-8").toSeq)
  }

  // ── Directory misses ───────────────────────────────────────────

  test("unknown identity → IdentityNotFound (no fallback)") {
    val f = buildFixture(Seq("alice@siida"))
    val res = IdentityEncryption.encrypt(
      f.directory,
      "unknown@siida".getBytes("UTF-8"),
      "no recipient".getBytes("UTF-8"),
      fixedRng("encrypt-miss"),
    )
    assertEquals(res, Left(IdentityEncError.IdentityNotFound))
  }

  // ── Cross-recipient: bob can't decrypt alice's ciphertext ──────

  test("bob holding only bob's secret cannot decrypt alice-targeted ciphertext") {
    val f = buildFixture(Seq("alice@siida", "bob@siida"))
    val (bobSecret, _) = f.recipients("bob@siida")
    val ct = IdentityEncryption.encrypt(
      f.directory,
      "alice@siida".getBytes("UTF-8"),
      "for alice only".getBytes("UTF-8"),
      fixedRng("encrypt-cross"),
    ).toOption.get
    val res = IdentityEncryption.decrypt(bobSecret, ct)
    assertEquals(res, Left(IdentityEncError.DecapsulationFailed))
  }

  // ── Directory tamper ───────────────────────────────────────────

  test("tampered MultiSignedEntry → InvalidDirectorySignature on lookup") {
    val rosterPairs = (0 until 3).map(i =>
      PqSignature.generateKeyPair(fixedRng(s"pkg-tamper-$i")))
    val rosterSks = rosterPairs.map(_._1)
    val rosterPks = rosterPairs.map(_._2)

    val (_, alicePublic) = HybridOnion.generateBundle(fixedRng("recip-tamper"))
    val payload = HybridOnion.serialisePublicBundle(alicePublic)

    // Sign with the right roster keys (threshold 2 of 3)
    val msg = MultiSignedEntry.signedMessage(payload, pkgDst)
    val sigs = Seq(0, 1).map(i => (i, PqSignature.sign(rosterSks(i), msg)))
    val entry = MultiSignedEntry.assemble(payload, sigs).toOption.get

    // Tamper the entry's payload bytes (flip last byte) — verify
    // should return PayloadHashMismatch → InvalidDirectorySignature
    val tampered = MultiSignedEntry.serialiseEntry(entry)
    tampered(tampered.length - 1) = (tampered(tampered.length - 1) ^ 0x01).toByte
    val tamperedEntry = MultiSignedEntry.deserialiseEntry(tampered).toOption.get

    val idBytes = "alice@siida".getBytes("UTF-8")
    val key: IArray[Byte] = IArray.unsafeFromArray(idBytes)
    val directory = Directory.inMemory(
      Map(key -> (alicePublic, tamperedEntry)),
      rosterPks, 2, pkgDst,
    )

    val res = IdentityEncryption.encrypt(
      directory,
      idBytes,
      "won't get here".getBytes("UTF-8"),
      fixedRng("encrypt-tamper"),
    )
    assertEquals(res, Left(IdentityEncError.InvalidDirectorySignature))
  }

  // ── Serialisation / wire-format ────────────────────────────────

  test("serialise / deserialise round-trip on an IdentityCiphertext") {
    val f = buildFixture(Seq("alice@siida"))
    val (aliceSecret, _) = f.recipients("alice@siida")
    val ct = IdentityEncryption.encrypt(
      f.directory,
      "alice@siida".getBytes("UTF-8"),
      "round-trip".getBytes("UTF-8"),
      fixedRng("encrypt-ser"),
    ).toOption.get
    val bytes = IdentityEncryption.serialiseCiphertext(ct)
    val back = IdentityEncryption.deserialiseCiphertext(bytes).toOption.get
    val plain = IdentityEncryption.decrypt(aliceSecret, back).toOption.get
    assertEquals(plain.toSeq, "round-trip".getBytes("UTF-8").toSeq)
  }

  test("deserialiseCiphertext rejects unknown algorithm ID uniformly (FR-011)") {
    val f = buildFixture(Seq("alice@siida"))
    val ct = IdentityEncryption.encrypt(
      f.directory,
      "alice@siida".getBytes("UTF-8"),
      "alg-test".getBytes("UTF-8"),
      fixedRng("encrypt-alg"),
    ).toOption.get
    val bytes = IdentityEncryption.serialiseCiphertext(ct)
    bytes(0) = 0x42.toByte
    val res = IdentityEncryption.deserialiseCiphertext(bytes)
    assertEquals(res, Left(IdentityEncError.UnsupportedAlgorithm))
  }

  test("wire-format size: 1138 + |inner-payload-overhead|") {
    val f = buildFixture(Seq("alice@siida"))
    val ct = IdentityEncryption.encrypt(
      f.directory,
      "alice@siida".getBytes("UTF-8"),
      "wire-size".getBytes("UTF-8"),
      fixedRng("encrypt-size"),
    ).toOption.get
    val bytes = IdentityEncryption.serialiseCiphertext(ct)
    // 1 (alg-ID) + 1137 (HybridOnion fixed overhead) + AEAD ct =
    // 1138 + 9 (payload "wire-size") + 0 (AEAD tag already in 1137)
    // wait — HybridOnion.FixedOverhead = 1137 INCLUDES the 16-byte
    // Poly1305 tag but NOT the payload. So total = 1138 + payload-len.
    assertEquals(bytes.length, 1138 + "wire-size".getBytes("UTF-8").length)
  }
