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

package siida.sdk

import java.security.SecureRandom
import munit.FunSuite
import siida.crypto.api.{HybridOnion, PqSignature}
import siida.mixnet.api.{Coordinator, MixChain}
import siida.sdk.api.{PeerCatalog, SdkError, SiidaClient, SignedChatWire}

/** Spec 027 — signed-chat end-to-end at the SDK layer. */
final class SignedChatSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private def mkMixChain(label: String): (Vector[HybridOnion.HybridSecretBundle], Vector[HybridOnion.HybridPublicBundle]) =
    val pairs = (0 until 2).map(i => HybridOnion.generateBundle(fixedRng(s"$label-mix-$i"))).toVector
    (pairs.map(_._1), pairs.map(_._2))

  test("SC-001: alice signs → bob verifies via PqSignature.verify") {
    val (mixSks, mixPks) = mkMixChain("sgn")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("sgn-a"))
    val (bSk, bPk) = HybridOnion.generateBundle(fixedRng("sgn-b"))
    val (aSigSk, aSigPk) = PqSignature.generateKeyPair(fixedRng("sgn-a-sig"))
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("bob".getBytes("UTF-8")) -> PeerCatalog.Peer(bPk, 2L),
    ))
    val alice = SiidaClient.create(
      "alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog,
      signingKey = Some(aSigSk),
    )
    val bob = SiidaClient.create(
      "bob".getBytes("UTF-8"), bSk, bPk, 2L, mixPks, catalog,
    )
    val payload = "hi bob, this is signed alice".getBytes("UTF-8")
    val onion = alice.sendSignedChatMessage("bob".getBytes("UTF-8"), payload, fixedRng("sgn-snd")).toOption.get
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x11.toByte))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    assertEquals(result.deliveries.length, 1)
    val envBytes = MixChain.serialiseEnvelope(result.deliveries.head)
    val incoming = bob.deliver(envBytes).toOption.get
    incoming match
      case SiidaClient.IncomingMessage.SignedChat(senderId, p, sigBytes) =>
        assertEquals(senderId.toSeq, "alice".getBytes("UTF-8").toSeq)
        assertEquals(p.toSeq, payload.toSeq)
        // verify with the actual signing key
        val signedMsg = SignedChatWire.signedMessage(senderId, "bob".getBytes("UTF-8"), p)
        val sig = PqSignature.deserialiseSignature(sigBytes).toOption.get
        assert(PqSignature.verify(aSigPk, signedMsg, sig), "signature should verify")
      case other => fail(s"expected SignedChat, got $other")
  }

  test("SC-003: replaying alice→bob signed chat against charlie's identity fails") {
    val (aSigSk, aSigPk) = PqSignature.generateKeyPair(fixedRng("replay-sig"))
    val payload = "hi bob".getBytes("UTF-8")
    // Sender signs binding bob as recipient.
    val signedForBob = SignedChatWire.signedMessage("alice".getBytes("UTF-8"), "bob".getBytes("UTF-8"), payload)
    val sig = PqSignature.sign(aSigSk, signedForBob)
    // Replay: charlie computes the verification message binding HIS identity
    val signedForCharlie = SignedChatWire.signedMessage("alice".getBytes("UTF-8"), "charlie".getBytes("UTF-8"), payload)
    assert(!PqSignature.verify(aSigPk, signedForCharlie, sig),
      "signature must not verify under a different recipient binding")
  }

  test("sendSignedChatMessage without signing key returns SigningKeyMissing") {
    val (mixSks, mixPks) = mkMixChain("nokey")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("nokey-a"))
    val (_, bPk) = HybridOnion.generateBundle(fixedRng("nokey-b"))
    val _ = mixSks
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("bob".getBytes("UTF-8")) -> PeerCatalog.Peer(bPk, 2L),
    ))
    val alice = SiidaClient.create("alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog)
    assertEquals(alice.hasSigningKey, false)
    val res = alice.sendSignedChatMessage("bob".getBytes("UTF-8"), "hi".getBytes("UTF-8"), fixedRng("nokey-snd"))
    assertEquals(res, Left(SdkError.SigningKeyMissing))
  }

  test("hasSigningKey reports true when signing key was supplied") {
    val (mixSks, mixPks) = mkMixChain("hk")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("hk-a"))
    val (aSigSk, _) = PqSignature.generateKeyPair(fixedRng("hk-a-sig"))
    val _ = mixSks
    val catalog = PeerCatalog.inMemoryVerified(Map.empty)
    val alice = SiidaClient.create(
      "alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog,
      signingKey = Some(aSigSk),
    )
    assertEquals(alice.hasSigningKey, true)
  }
