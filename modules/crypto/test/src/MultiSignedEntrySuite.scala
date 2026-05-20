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

/** Spec 014 — MultiSignedEntry verifier tests. */
final class MultiSignedEntrySuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private val dst = "siida/test/v1/mse".getBytes("UTF-8")

  /** Helper: roster of `n` signers from fixed-seed keys. */
  private def roster(n: Int): (Seq[PqSignature.PqPrivateKey], Seq[PqSignature.PqPublicKey]) =
    val pairs = (0 until n).map(i => PqSignature.generateKeyPair(fixedRng(s"roster-$i")))
    (pairs.map(_._1), pairs.map(_._2))

  /** Helper: sign a payload with the given signers (by roster index). */
  private def sign(payload: Array[Byte], sks: Seq[(Int, PqSignature.PqPrivateKey)])
    : Seq[(Int, PqSignature.Signature)] =
    val msg = MultiSignedEntry.signedMessage(payload, dst)
    sks.map((idx, sk) => (idx, PqSignature.sign(sk, msg)))

  // ── Happy-path verify ──────────────────────────────────────────

  test("3-of-5 valid signatures verify under threshold 3") {
    val (sks, pks) = roster(5)
    val payload = "siida/test payload-1".getBytes("UTF-8")
    val sigs = sign(payload, Seq(0, 2, 4).map(i => (i, sks(i))))
    val entry = MultiSignedEntry.assemble(payload, sigs).toOption.get
    assertEquals(MultiSignedEntry.verify(pks, 3, dst, entry), VerifyResult.Valid)
  }

  test("5-of-5 valid signatures verify under threshold 3 (overshoot is OK)") {
    val (sks, pks) = roster(5)
    val payload = "siida/test payload-2".getBytes("UTF-8")
    val sigs = sign(payload, (0 until 5).map(i => (i, sks(i))))
    val entry = MultiSignedEntry.assemble(payload, sigs).toOption.get
    assertEquals(MultiSignedEntry.verify(pks, 3, dst, entry), VerifyResult.Valid)
  }

  // ── Threshold violations ───────────────────────────────────────

  test("2-of-5 valid signatures fall short of threshold 3 → ThresholdNotMet(2, 3)") {
    val (sks, pks) = roster(5)
    val payload = "siida/test payload-3".getBytes("UTF-8")
    val sigs = sign(payload, Seq(0, 2).map(i => (i, sks(i))))
    val entry = MultiSignedEntry.assemble(payload, sigs).toOption.get
    assertEquals(MultiSignedEntry.verify(pks, 3, dst, entry),
      VerifyResult.ThresholdNotMet(2, 3))
  }

  // ── Tamper / forgery rejections ────────────────────────────────

  test("tampered payload triggers PayloadHashMismatch") {
    val (sks, pks) = roster(3)
    val payload = "original".getBytes("UTF-8")
    val sigs = sign(payload, Seq(0, 1, 2).map(i => (i, sks(i))))
    val entry = MultiSignedEntry.assemble(payload, sigs).toOption.get
    // Flip a byte in the payload region — payload sits at the tail
    val tampered = MultiSignedEntry.serialiseEntry(entry)
    tampered(tampered.length - 1) = (tampered(tampered.length - 1) ^ 0x01).toByte
    val reparsed = MultiSignedEntry.deserialiseEntry(tampered).toOption.get
    assertEquals(MultiSignedEntry.verify(pks, 3, dst, reparsed),
      VerifyResult.PayloadHashMismatch)
  }

  test("wrong DST tag → ThresholdNotMet (signatures invalid under different tag)") {
    val (sks, pks) = roster(3)
    val payload = "dst-test".getBytes("UTF-8")
    val sigs = sign(payload, Seq(0, 1, 2).map(i => (i, sks(i))))
    val entry = MultiSignedEntry.assemble(payload, sigs).toOption.get
    val otherDst = "siida/test/v1/OTHER".getBytes("UTF-8")
    val res = MultiSignedEntry.verify(pks, 3, otherDst, entry)
    res match
      case VerifyResult.ThresholdNotMet(0, 3) => () // expected
      case other                              => fail(s"expected ThresholdNotMet(0,3), got $other")
  }

  test("duplicate signer_index in assemble is rejected") {
    val (sks, _) = roster(3)
    val payload = "dup-test".getBytes("UTF-8")
    val sigs = sign(payload, Seq((1, sks(1)), (1, sks(1)))) // index 1 twice
    val res = MultiSignedEntry.assemble(payload, sigs)
    res match
      case Left(MultiSignedEntryError.DuplicateSignerIndex(1)) => ()
      case other => fail(s"expected DuplicateSignerIndex(1), got $other")
  }

  test("signer_index out of roster bounds → InvalidSignerIndex") {
    val (sks, pks) = roster(3)
    val payload = "oob-test".getBytes("UTF-8")
    // Sign with sk[1] but claim signer_index 5 (out of roster)
    val signedMsg = MultiSignedEntry.signedMessage(payload, dst)
    val sigs = Seq((5, PqSignature.sign(sks(1), signedMsg)))
    val entry = MultiSignedEntry.assemble(payload, sigs).toOption.get
    assertEquals(MultiSignedEntry.verify(pks, 1, dst, entry),
      VerifyResult.InvalidSignerIndex(5))
  }

  // ── Serialisation / wire-format ────────────────────────────────

  test("serialise / deserialise round-trip preserves verify result") {
    val (sks, pks) = roster(4)
    val payload = "ser-roundtrip".getBytes("UTF-8")
    val sigs = sign(payload, Seq(0, 1, 2, 3).map(i => (i, sks(i))))
    val entry = MultiSignedEntry.assemble(payload, sigs).toOption.get
    val bytes = MultiSignedEntry.serialiseEntry(entry)
    val back = MultiSignedEntry.deserialiseEntry(bytes).toOption.get
    assertEquals(MultiSignedEntry.verify(pks, 4, dst, back), VerifyResult.Valid)
  }

  test("deserialise rejects too-short input with InvalidLength") {
    val res = MultiSignedEntry.deserialiseEntry(new Array[Byte](10))
    assertEquals(res, Left(MultiSignedEntryError.InvalidLength))
  }

  test("deserialise rejects unknown FormatVersion with UnsupportedVersion") {
    val (sks, _) = roster(2)
    val payload = "ver-test".getBytes("UTF-8")
    val sigs = sign(payload, Seq(0, 1).map(i => (i, sks(i))))
    val entry = MultiSignedEntry.assemble(payload, sigs).toOption.get
    val bytes = MultiSignedEntry.serialiseEntry(entry)
    bytes(0) = 0x99.toByte // unknown version
    val res = MultiSignedEntry.deserialiseEntry(bytes)
    assertEquals(res, Left(MultiSignedEntryError.UnsupportedVersion))
  }

  test("wire-format size matches the documented formula: 35 + n×3312 + |payload|") {
    val (sks, _) = roster(3)
    val payload = "size-check".getBytes("UTF-8")
    val sigs = sign(payload, Seq(0, 1, 2).map(i => (i, sks(i))))
    val entry = MultiSignedEntry.assemble(payload, sigs).toOption.get
    val bytes = MultiSignedEntry.serialiseEntry(entry)
    assertEquals(bytes.length, 35 + 3 * 3312 + payload.length,
      "wire-format size formula broken — see 014 contracts/wire-format.md")
  }
