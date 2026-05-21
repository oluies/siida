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

/** Spec 023 — ChatSession.sendChat uses the authenticated path so
 *  inbound chats resolve the sender alias from the FriendStore.
 */
final class ChatSessionAuthenticatedSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private def mkMixChain(label: String): (Vector[HybridOnion.HybridSecretBundle], Vector[HybridOnion.HybridPublicBundle]) =
    val pairs = (0 until 2).map(i => HybridOnion.generateBundle(fixedRng(s"$label-mix-$i"))).toVector
    (pairs.map(_._1), pairs.map(_._2))

  test("SC-002: alice → bob via ChatSession surfaces Inbound(\"alice\", ...) (not \"?\")") {
    val (mixSks, mixPks) = mkMixChain("cs-auth")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("cs-auth-a"))
    val (bSk, bPk) = HybridOnion.generateBundle(fixedRng("cs-auth-b"))
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

    val onion = a.sendChat("bob", "hi bob", fixedRng("cs-auth-snd")).toOption.get
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x11.toByte))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    val envBytes = MixChain.serialiseEnvelope(result.deliveries.head)
    val event = b.deliverInbound(envBytes).toOption.get
    event match
      case ChatSession.InboundEvent.Chat(line) =>
        // Per spec 023 SC-001: alias is resolved from FriendStore
        assertEquals(line.fromAlias, "alice")
        assertEquals(line.text, "hi bob")
      case other => fail(s"expected Chat, got $other")
  }

  test("SC-002 fallback: unknown sender (not in bob's FriendStore) → Inbound(\"?\", ...)") {
    val (mixSks, mixPks) = mkMixChain("cs-uk")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("cs-uk-a"))
    val (bSk, bPk) = HybridOnion.generateBundle(fixedRng("cs-uk-b"))
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("alice".getBytes("UTF-8")) -> PeerCatalog.Peer(aPk, 1L),
      IArray.unsafeFromArray("bob".getBytes("UTF-8"))   -> PeerCatalog.Peer(bPk, 2L),
    ))
    val aliceSdk = SiidaClient.create("alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog)
    val bobSdk   = SiidaClient.create("bob".getBytes("UTF-8"),   bSk, bPk, 2L, mixPks, catalog)

    // Alice has bob in her store; bob does NOT have alice in his.
    val aliceFS = FriendStore.inMemory(); aliceFS.add("bob".getBytes("UTF-8"), bPk)
    val bobFS   = FriendStore.inMemory()

    val a = ChatSession.create("alice", aliceSdk, aliceFS)
    val b = ChatSession.create("bob",   bobSdk,   bobFS)

    val onion = a.sendChat("bob", "hi stranger", fixedRng("cs-uk-snd")).toOption.get
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x22.toByte))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    val envBytes = MixChain.serialiseEnvelope(result.deliveries.head)
    val event = b.deliverInbound(envBytes).toOption.get
    event match
      case ChatSession.InboundEvent.Chat(line) =>
        assertEquals(line.fromAlias, "?", "unknown sender must fall back to '?'")
        assertEquals(line.text, "hi stranger")
      case other => fail(s"expected Chat, got $other")
  }

  test("SC-003: plain ChatMessage path (no SiidaClient sender) still surfaces as Inbound(\"?\", ...)") {
    val (mixSks, mixPks) = mkMixChain("cs-plain")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("cs-plain-a"))
    val (bSk, bPk) = HybridOnion.generateBundle(fixedRng("cs-plain-b"))
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("bob".getBytes("UTF-8")) -> PeerCatalog.Peer(bPk, 2L),
    ))
    val aliceSdk = SiidaClient.create("alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog)
    val bobSdk   = SiidaClient.create("bob".getBytes("UTF-8"),   bSk, bPk, 2L, mixPks, catalog)
    val bobFS    = FriendStore.inMemory(); bobFS.add("alice".getBytes("UTF-8"), aPk)
    val b        = ChatSession.create("bob", bobSdk, bobFS)

    // Send via the plain path directly through the SDK
    val onion = aliceSdk.sendChatMessage("bob".getBytes("UTF-8"), "plain hi".getBytes("UTF-8"), fixedRng("cs-plain-snd")).toOption.get
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x33.toByte))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    val envBytes = MixChain.serialiseEnvelope(result.deliveries.head)
    val event = b.deliverInbound(envBytes).toOption.get
    event match
      case ChatSession.InboundEvent.Chat(line) =>
        assertEquals(line.fromAlias, "?", "plain chat has no sender on the wire")
        assertEquals(line.text, "plain hi")
      case other => fail(s"expected Chat, got $other")
  }
