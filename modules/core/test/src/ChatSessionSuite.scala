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
import siida.crypto.api.HybridOnion
import siida.mixnet.api.{Coordinator, MixChain}
import siida.pkg.api.FriendStore
import siida.sdk.api.{PeerCatalog, SiidaClient}

final class ChatSessionSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private def mkMixChain(label: String): (Vector[HybridOnion.HybridSecretBundle], Vector[HybridOnion.HybridPublicBundle]) =
    val pairs = (0 until 2).map(i => HybridOnion.generateBundle(fixedRng(s"$label-mix-$i"))).toVector
    (pairs.map(_._1), pairs.map(_._2))

  test("SC-001: alice → bob chat via ChatSession round-trips") {
    val (mixSks, mixPks) = mkMixChain("cs")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("cs-a"))
    val (bSk, bPk) = HybridOnion.generateBundle(fixedRng("cs-b"))

    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("alice".getBytes("UTF-8")) -> PeerCatalog.Peer(aPk, 1L),
      IArray.unsafeFromArray("bob".getBytes("UTF-8"))   -> PeerCatalog.Peer(bPk, 2L),
    ))
    val aliceSdk = SiidaClient.create("alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog)
    val bobSdk   = SiidaClient.create("bob".getBytes("UTF-8"),   bSk, bPk, 2L, mixPks, catalog)

    val aliceFS = FriendStore.inMemory()
    aliceFS.add("bob".getBytes("UTF-8"), bPk)
    val bobFS = FriendStore.inMemory()
    bobFS.add("alice".getBytes("UTF-8"), aPk)

    val aliceSes = ChatSession.create("alice", aliceSdk, aliceFS)
    val bobSes   = ChatSession.create("bob",   bobSdk,   bobFS)

    val onion = aliceSes.sendChat("bob", "hi bob", fixedRng("cs-snd")).toOption.get
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x11.toByte))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    assertEquals(result.deliveries.length, 1)
    val envBytes = MixChain.serialiseEnvelope(result.deliveries.head)
    val event = bobSes.deliverInbound(envBytes).toOption.get
    event match
      case ChatSession.InboundEvent.Chat(line) =>
        assertEquals(line.text, "hi bob")
      case other => fail(s"expected Chat, got $other")

    // History: alice has one outbound, bob has one inbound
    assertEquals(aliceSes.history.length, 1)
    assertEquals(bobSes.history.length, 1)
  }

  test("send to unknown alias → UnknownFriend") {
    val (_, mixPks) = mkMixChain("uk")
    val (sk, pk) = HybridOnion.generateBundle(fixedRng("uk"))
    val catalog = PeerCatalog.inMemoryVerified(Map.empty)
    val sdk = SiidaClient.create("alice".getBytes("UTF-8"), sk, pk, 1L, mixPks, catalog)
    val fs = FriendStore.inMemory()
    val ses = ChatSession.create("alice", sdk, fs)
    val res = ses.sendChat("ghost", "hi", fixedRng("uk-snd"))
    res match
      case Left(ChatSession.SessionError.UnknownFriend("ghost")) => ()
      case other => fail(s"expected UnknownFriend, got $other")
  }

  test("friends list reflects the FriendStore (insertion order)") {
    val (_, mixPks) = mkMixChain("fl")
    val (sk, pk) = HybridOnion.generateBundle(fixedRng("fl"))
    val sdk = SiidaClient.create("alice".getBytes("UTF-8"), sk, pk, 1L, mixPks, PeerCatalog.inMemoryVerified(Map.empty))
    val fs = FriendStore.inMemory()
    val (_, b1) = HybridOnion.generateBundle(fixedRng("fl-b"))
    val (_, b2) = HybridOnion.generateBundle(fixedRng("fl-c"))
    fs.add("bob".getBytes("UTF-8"), b1)
    fs.add("carol".getBytes("UTF-8"), b2)
    val ses = ChatSession.create("alice", sdk, fs)
    assertEquals(ses.friends, Vector("bob", "carol"))
  }

  test("lookup recovers identity bytes + bundle") {
    val (_, mixPks) = mkMixChain("lk")
    val (sk, pk) = HybridOnion.generateBundle(fixedRng("lk"))
    val sdk = SiidaClient.create("alice".getBytes("UTF-8"), sk, pk, 1L, mixPks, PeerCatalog.inMemoryVerified(Map.empty))
    val fs = FriendStore.inMemory()
    val (_, bpk) = HybridOnion.generateBundle(fixedRng("lk-b"))
    fs.add("bob".getBytes("UTF-8"), bpk)
    val ses = ChatSession.create("alice", sdk, fs)
    val res = ses.lookup("bob").get
    assertEquals(res._1.toSeq, "bob".getBytes("UTF-8").toSeq)
    assertEquals(
      HybridOnion.serialisePublicBundle(res._2).toSeq,
      HybridOnion.serialisePublicBundle(bpk).toSeq)
  }

  test("SC-002: history preserves the order of outbound + inbound events") {
    val (mixSks, mixPks) = mkMixChain("ord")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("ord-a"))
    val (bSk, bPk) = HybridOnion.generateBundle(fixedRng("ord-b"))
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("alice".getBytes("UTF-8")) -> PeerCatalog.Peer(aPk, 1L),
      IArray.unsafeFromArray("bob".getBytes("UTF-8"))   -> PeerCatalog.Peer(bPk, 2L),
    ))
    val aliceSdk = SiidaClient.create("alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog)
    val bobSdk   = SiidaClient.create("bob".getBytes("UTF-8"),   bSk, bPk, 2L, mixPks, catalog)
    val aliceFS = FriendStore.inMemory(); aliceFS.add("bob".getBytes("UTF-8"), bPk)
    val bobFS   = FriendStore.inMemory(); bobFS.add("alice".getBytes("UTF-8"), aPk)
    val a = ChatSession.create("alice", aliceSdk, aliceFS)
    val b = ChatSession.create("bob",   bobSdk,   bobFS)

    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x22.toByte))

    // Outbound a → b
    val o1 = a.sendChat("bob", "first", fixedRng("ord-1")).toOption.get
    val env1 = MixChain.serialiseEnvelope(Coordinator.runRound(Vector(o1), mixSks, seeds).deliveries.head)
    b.deliverInbound(env1).toOption.get

    // Outbound b → a
    val o2 = b.sendChat("alice", "second", fixedRng("ord-2")).toOption.get
    val env2 = MixChain.serialiseEnvelope(Coordinator.runRound(Vector(o2), mixSks, seeds).deliveries.head)
    a.deliverInbound(env2).toOption.get

    assertEquals(a.history.length, 2)
    assertEquals(b.history.length, 2)
    a.history(0) match
      case ChatSession.ChatLine.Outbound(_, t) => assertEquals(t, "first")
      case other => fail(s"$other")
    a.history(1) match
      case ChatSession.ChatLine.Inbound(_, t)  => assertEquals(t, "second")
      case other => fail(s"$other")
  }
