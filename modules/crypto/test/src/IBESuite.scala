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

/** Boneh-Franklin IBE over BN254 — round-trip + wrong-identity refusal +
 *  cross-fixture determinism. KAT vectors against an external reference
 *  are a follow-up; this suite catches regressions in the IBE
 *  construction itself.
 *
 *  All tests use a documented deterministic SHA1PRNG seed so outputs
 *  are reproducible across runs and architectures (FR-006, SC-002).
 */
final class IBESuite extends FunSuite:

  /** Build a deterministic SecureRandom from a fixed seed string. */
  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private val alice   = "alice@siida".getBytes("UTF-8")
  private val bob     = "bob@siida".getBytes("UTF-8")
  private val message = "hello siida".getBytes("UTF-8")

  test("round-trip: encrypt with MPK + identity, decrypt with matching identity key, recover plaintext") {
    val mk  = IBE.generateMasterKey(fixedRng("test/master-key"))
    val mpk = IBE.publicKey(mk)
    val idk = IBE.issueKey(mk, alice)

    val ct  = IBE.encrypt(mpk, alice, message, fixedRng("test/encrypt-r"))
    val out = IBE.decrypt(idk, ct)

    out match
      case Right(recovered) =>
        assertEquals(recovered.toSeq, message.toSeq,
          "round-trip plaintext mismatch")
      case Left(err) =>
        fail(s"decrypt returned Left($err), expected Right(message)")
  }

  test("wrong-identity refusal: decrypt with the wrong identity key returns Left(WrongIdentity)") {
    val mk  = IBE.generateMasterKey(fixedRng("test/master-key-wrong-id"))
    val mpk = IBE.publicKey(mk)
    val ctForAlice = IBE.encrypt(mpk, alice, message, fixedRng("test/encrypt-wrong-id"))

    val bobKey = IBE.issueKey(mk, bob)
    val out    = IBE.decrypt(bobKey, ctForAlice)

    assertEquals(out, Left(IBEError.WrongIdentity),
      "decrypt with Bob's key on Alice's ciphertext must be WrongIdentity")
  }

  test("determinism: same seed + same inputs produce identical ciphertexts") {
    val mk1 = IBE.generateMasterKey(fixedRng("determinism/master"))
    val mk2 = IBE.generateMasterKey(fixedRng("determinism/master"))

    val mpk1 = IBE.serialiseMasterPublicKey(IBE.publicKey(mk1))
    val mpk2 = IBE.serialiseMasterPublicKey(IBE.publicKey(mk2))
    assertEquals(mpk1.toSeq, mpk2.toSeq, "MPK should be deterministic from seed")

    val idk1 = IBE.serialiseIdentityKey(IBE.issueKey(mk1, alice))
    val idk2 = IBE.serialiseIdentityKey(IBE.issueKey(mk2, alice))
    assertEquals(idk1.toSeq, idk2.toSeq, "IdentityKey should be deterministic from seed")

    val ct1 = IBE.serialiseCiphertext(
      IBE.encrypt(IBE.publicKey(mk1), alice, message, fixedRng("determinism/encrypt")))
    val ct2 = IBE.serialiseCiphertext(
      IBE.encrypt(IBE.publicKey(mk2), alice, message, fixedRng("determinism/encrypt")))
    assertEquals(ct1.toSeq, ct2.toSeq, "Ciphertext should be deterministic from seed")
  }

  test("serialise / deserialise round-trip for MasterPublicKey") {
    val mk    = IBE.generateMasterKey(fixedRng("ser/mpk"))
    val mpk   = IBE.publicKey(mk)
    val bytes = IBE.serialiseMasterPublicKey(mpk)
    val back  = IBE.deserialiseMasterPublicKey(bytes)
    back match
      case Right(mpk2) =>
        assertEquals(
          IBE.serialiseMasterPublicKey(mpk2).toSeq, bytes.toSeq,
          "MPK round-trip mismatch")
      case Left(err) => fail(s"deserialise rejected our own bytes: $err")
  }

  test("serialise / deserialise round-trip for IdentityKey") {
    val mk    = IBE.generateMasterKey(fixedRng("ser/idk"))
    val idk   = IBE.issueKey(mk, alice)
    val bytes = IBE.serialiseIdentityKey(idk)
    val back  = IBE.deserialiseIdentityKey(bytes)
    back match
      case Right(idk2) =>
        assertEquals(
          IBE.serialiseIdentityKey(idk2).toSeq, bytes.toSeq,
          "IdentityKey round-trip mismatch")
      case Left(err) => fail(s"deserialise rejected our own bytes: $err")
  }

  test("serialise / deserialise round-trip for Ciphertext, then decrypt") {
    val mk    = IBE.generateMasterKey(fixedRng("ser/ct"))
    val mpk   = IBE.publicKey(mk)
    val idk   = IBE.issueKey(mk, alice)
    val ct    = IBE.encrypt(mpk, alice, message, fixedRng("ser/ct-r"))
    val bytes = IBE.serialiseCiphertext(ct)

    IBE.deserialiseCiphertext(bytes) match
      case Right(ct2) =>
        IBE.decrypt(idk, ct2) match
          case Right(recovered) =>
            assertEquals(recovered.toSeq, message.toSeq,
              "ciphertext round-trip changed the plaintext")
          case Left(err) => fail(s"decrypt of deserialised ct failed: $err")
      case Left(err) => fail(s"deserialise rejected our own bytes: $err")
  }

  test("malformed ciphertext rejected by deserialise") {
    val tooShort = new Array[Byte](10)
    val res = IBE.deserialiseCiphertext(tooShort)
    assert(res.isLeft, s"expected Left for 10-byte input; got $res")
  }
