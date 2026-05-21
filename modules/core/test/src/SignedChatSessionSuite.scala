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

package siida.core

import java.security.SecureRandom
import munit.FunSuite
import siida.core.api.ChatSession
import siida.crypto.api.{HybridOnion, PqSignature}
import siida.mixnet.api.{Coordinator, MixChain}
import siida.pkg.api.FriendStore
import siida.sdk.api.{PeerCatalog, SiidaClient, SignedChatWire}

/** Spec 027 — signed-chat end-to-end via ChatSession. */
final class SignedChatSessionSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private def mkChain(label: String): (Vector[HybridOnion.HybridSecretBundle], Vector[HybridOnion.HybridPublicBundle]) =
    val pairs = (0 until 2).map(i => HybridOnion.generateBundle(fixedRng(s"$label-mix-$i"))).toVector
    (pairs.map(_._1), pairs.map(_._2))

  private def relay(
    onion: HybridOnion.OnionLayer,
    mixSks: Vector[HybridOnion.HybridSecretBundle],
    seed: Byte,
  ): Array[Byte] =
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(seed))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    MixChain.serialiseEnvelope(result.deliveries.head)

  /** Two paired sessions (alice, bob) with ML-DSA-65 signing keys
   *  registered in each other's FriendStore.
   */
  private case class Pair(
    alice: ChatSession,
    bob:   ChatSession,
    mixSks: Vector[HybridOnion.HybridSecretBundle],
    aSigPk: PqSignature.PqPublicKey,
    bSigPk: PqSignature.PqPublicKey,
  )

  private def mkPair(label: String, registerAliceKeyForBob: Boolean = true): Pair =
    val (mixSks, mixPks) = mkChain(label)
    val (aSk, aPk)       = HybridOnion.generateBundle(fixedRng(s"$label-a"))
    val (bSk, bPk)       = HybridOnion.generateBundle(fixedRng(s"$label-b"))
    val (aSigSk, aSigPk) = PqSignature.generateKeyPair(fixedRng(s"$label-a-sig"))
    val (bSigSk, bSigPk) = PqSignature.generateKeyPair(fixedRng(s"$label-b-sig"))
    val aliceId = "alice".getBytes("UTF-8")
    val bobId   = "bob".getBytes("UTF-8")
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray(aliceId) -> PeerCatalog.Peer(aPk, 1L),
      IArray.unsafeFromArray(bobId)   -> PeerCatalog.Peer(bPk, 2L),
    ))
    val aliceSdk = SiidaClient.create(aliceId, aSk, aPk, 1L, mixPks, catalog, signingKey = Some(aSigSk))
    val bobSdk   = SiidaClient.create(bobId,   bSk, bPk, 2L, mixPks, catalog, signingKey = Some(bSigSk))
    val aliceFs = FriendStore.inMemory()
    val bobFs   = FriendStore.inMemory()
    aliceFs.addWithSigningKey(bobId, bPk, bSigPk)
    if registerAliceKeyForBob then
      bobFs.addWithSigningKey(aliceId, aPk, aSigPk)
    else
      bobFs.add(aliceId, aPk)
    Pair(
      alice  = ChatSession.create("alice", aliceSdk, aliceFs),
      bob    = ChatSession.create("bob",   bobSdk,   bobFs),
      mixSks = mixSks,
      aSigPk = aSigPk,
      bSigPk = bSigPk,
    )

  test("SC-001: signed chat alice→bob verifies and surfaces alice as sender") {
    val p = mkPair("happy")
    val onion = p.alice.sendChat("bob", "hi bob signed", fixedRng("happy-snd")).toOption.get
    val envBytes = relay(onion, p.mixSks, 0x11.toByte)
    val ev = p.bob.deliverInbound(envBytes).toOption.get
    ev match
      case ChatSession.InboundEvent.Chat(line) =>
        assertEquals(line.fromAlias, "alice")
        assertEquals(line.text, "hi bob signed")
      case other => fail(s"expected Chat, got $other")
    assertEquals(p.bob.history.length, 1)
  }

  test("SC-002: tampered sender_id (without re-sign) → SignatureFailed") {
    // We build a signed chat alice→bob, then forge a sibling envelope
    // claiming sender=mallory whose signing pk happens to be in bob's
    // FriendStore but won't validate this signature.
    val (mixSks, mixPks) = mkChain("forge")
    val (aSk, aPk)       = HybridOnion.generateBundle(fixedRng("forge-a"))
    val (bSk, bPk)       = HybridOnion.generateBundle(fixedRng("forge-b"))
    val (mSk, mPk)       = HybridOnion.generateBundle(fixedRng("forge-m"))
    val (aSigSk, aSigPk) = PqSignature.generateKeyPair(fixedRng("forge-a-sig"))
    val (mSigSk, mSigPk) = PqSignature.generateKeyPair(fixedRng("forge-m-sig"))
    val _ = (aSigSk, mSk, mSigPk)
    val aliceId = "alice".getBytes("UTF-8")
    val bobId   = "bob".getBytes("UTF-8")
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray(bobId) -> PeerCatalog.Peer(bPk, 2L),
    ))
    // Mallory holds her own SDK with her own signing key and constructs
    // an envelope claiming to be `alice`. Bob's FriendStore has alice's
    // real signing public key — Mallory's signature won't verify.
    val mallory = SiidaClient.create(
      aliceId, // claim alice's identity bytes (the attack)
      mSk, mPk, 3L, mixPks, catalog,
      signingKey = Some(mSigSk),
    )
    val bobSdk = SiidaClient.create(bobId, bSk, bPk, 2L, mixPks, catalog)
    val bobFs = FriendStore.inMemory()
    bobFs.addWithSigningKey(aliceId, aPk, aSigPk) // bob knows real alice
    val bob = ChatSession.create("bob", bobSdk, bobFs)

    val onion = mallory.sendSignedChatMessage(bobId, "i am alice".getBytes("UTF-8"), fixedRng("forge-snd")).toOption.get
    val envBytes = relay(onion, mixSks, 0x22.toByte)
    val res = bob.deliverInbound(envBytes)
    assertEquals(res, Left(ChatSession.SessionError.SignatureFailed))
    assertEquals(bob.history.length, 0)
  }

  test("SC-004: missing signing key for sender → unverified alias") {
    val p = mkPair("missing", registerAliceKeyForBob = false)
    // bob's FriendStore has alice's bundle but NOT her signing key
    val onion = p.alice.sendChat("bob", "hi (unverifiable)", fixedRng("missing-snd")).toOption.get
    val envBytes = relay(onion, p.mixSks, 0x33.toByte)
    val ev = p.bob.deliverInbound(envBytes).toOption.get
    ev match
      case ChatSession.InboundEvent.Chat(line) =>
        assertEquals(line.fromAlias, "?[unverified]")
        assertEquals(line.text, "hi (unverifiable)")
      case other => fail(s"expected Chat, got $other")
  }

  test("SC-005: sendChat falls back to authenticated path when SDK has no signing key") {
    val (mixSks, mixPks) = mkChain("fb")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("fb-a"))
    val (bSk, bPk) = HybridOnion.generateBundle(fixedRng("fb-b"))
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("bob".getBytes("UTF-8")) -> PeerCatalog.Peer(bPk, 2L),
    ))
    // No signing key — should use 0x03 path
    val aliceSdk = SiidaClient.create("alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog)
    val bobSdk   = SiidaClient.create("bob".getBytes("UTF-8"),   bSk, bPk, 2L, mixPks, catalog)
    val aliceFs = FriendStore.inMemory()
    aliceFs.add("bob".getBytes("UTF-8"), bPk)
    val bobFs = FriendStore.inMemory()
    bobFs.add("alice".getBytes("UTF-8"), aPk)
    val alice = ChatSession.create("alice", aliceSdk, aliceFs)
    val bob   = ChatSession.create("bob",   bobSdk,   bobFs)
    val onion = alice.sendChat("bob", "hi fallback", fixedRng("fb-snd")).toOption.get
    val envBytes = relay(onion, mixSks, 0x44.toByte)
    val ev = bob.deliverInbound(envBytes).toOption.get
    ev match
      case ChatSession.InboundEvent.Chat(line) =>
        // Bob's FriendStore has alice's bundle (no signing key, but
        // it's a 0x03 envelope so authenticated path resolves alias).
        assertEquals(line.fromAlias, "alice")
        assertEquals(line.text, "hi fallback")
      case other => fail(s"expected Chat, got $other")
  }

  test("signedMessage binding: changing the recipient changes the signed bytes") {
    // Sanity check at the ChatSession layer — same as in SignedChatWireSuite,
    // here to lock in the binding from the session-layer perspective.
    val a = "alice".getBytes("UTF-8")
    val b = "bob".getBytes("UTF-8")
    val c = "charlie".getBytes("UTF-8")
    val p = "hi".getBytes("UTF-8")
    val mAB = SignedChatWire.signedMessage(a, b, p)
    val mAC = SignedChatWire.signedMessage(a, c, p)
    assert(!java.util.Arrays.equals(mAB, mAC))
  }
