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
import siida.crypto.api.HybridOnion
import siida.mixnet.api.{Coordinator, MixChain}
import siida.sdk.api.{AuthenticatedChatWire, PeerCatalog, SdkError, SiidaClient}

/** Spec 023 — sendAuthenticatedChatMessage + IncomingMessage.AuthenticatedChat. */
final class AuthenticatedChatSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private def mkMixChain(label: String): (Vector[HybridOnion.HybridSecretBundle], Vector[HybridOnion.HybridPublicBundle]) =
    val pairs = (0 until 2).map(i => HybridOnion.generateBundle(fixedRng(s"$label-mix-$i"))).toVector
    (pairs.map(_._1), pairs.map(_._2))

  test("SC-001: alice → bob authenticated chat surfaces sender identity") {
    val (mixSks, mixPks) = mkMixChain("auth")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("auth-a"))
    val (bSk, bPk) = HybridOnion.generateBundle(fixedRng("auth-b"))
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("alice".getBytes("UTF-8")) -> PeerCatalog.Peer(aPk, 1L),
      IArray.unsafeFromArray("bob".getBytes("UTF-8"))   -> PeerCatalog.Peer(bPk, 2L),
    ))
    val alice = SiidaClient.create("alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog)
    val bob   = SiidaClient.create("bob".getBytes("UTF-8"),   bSk, bPk, 2L, mixPks, catalog)

    val payload = "hi bob, this is alice".getBytes("UTF-8")
    val onion = alice.sendAuthenticatedChatMessage("bob".getBytes("UTF-8"), payload, fixedRng("auth-snd")).toOption.get

    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x77.toByte))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    assertEquals(result.deliveries.length, 1)
    val envBytes = MixChain.serialiseEnvelope(result.deliveries.head)
    val incoming = bob.deliver(envBytes).toOption.get
    incoming match
      case SiidaClient.IncomingMessage.AuthenticatedChat(senderId, p) =>
        assertEquals(senderId.toSeq, "alice".getBytes("UTF-8").toSeq)
        assertEquals(p.toSeq, payload.toSeq)
      case other => fail(s"expected AuthenticatedChat, got $other")
  }

  test("SC-004: tampered authenticated envelope → DecryptionFailed") {
    val (mixSks, mixPks) = mkMixChain("tamp")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("tamp-a"))
    val (bSk, bPk) = HybridOnion.generateBundle(fixedRng("tamp-b"))
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("bob".getBytes("UTF-8")) -> PeerCatalog.Peer(bPk, 2L),
    ))
    val alice = SiidaClient.create("alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog)
    val bob   = SiidaClient.create("bob".getBytes("UTF-8"),   bSk, bPk, 2L, mixPks, catalog)

    val onion = alice.sendAuthenticatedChatMessage("bob".getBytes("UTF-8"), "hi".getBytes("UTF-8"), fixedRng("tamp-snd")).toOption.get
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x33.toByte))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    val envBytes = MixChain.serialiseEnvelope(result.deliveries.head)
    envBytes(envBytes.length - 1) = (envBytes(envBytes.length - 1) ^ 0x01).toByte
    val res = bob.deliver(envBytes)
    assertEquals(res, Left(SdkError.DecryptionFailed))
  }

  test("AuthenticatedChatWire: encode → decode round-trip") {
    val id = "alice".getBytes("UTF-8")
    val payload = "hello".getBytes("UTF-8")
    val bytes = AuthenticatedChatWire.encode(id, payload)
    val (gotId, gotPayload) = AuthenticatedChatWire.decode(bytes).toOption.get
    assertEquals(gotId.toSeq, id.toSeq)
    assertEquals(gotPayload.toSeq, payload.toSeq)
  }

  test("AuthenticatedChatWire: empty sender identity → MalformedEnvelope") {
    val bytes = AuthenticatedChatWire.encode(Array.emptyByteArray, "x".getBytes("UTF-8"))
    val res = AuthenticatedChatWire.decode(bytes)
    res match
      case Left(SdkError.MalformedEnvelope(_)) => ()
      case other => fail(s"expected MalformedEnvelope, got $other")
  }

  test("AuthenticatedChatWire: truncated input → MalformedEnvelope") {
    // Declare 100-byte sender id but only provide 4 bytes total
    val bytes = Array[Byte](0x00, 100.toByte, 0x41, 0x42)
    val res = AuthenticatedChatWire.decode(bytes)
    assert(res.isLeft, s"expected Left for truncated input, got $res")
  }

  test("plain ChatMessage path still works (backward compat)") {
    val (mixSks, mixPks) = mkMixChain("bc")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("bc-a"))
    val (bSk, bPk) = HybridOnion.generateBundle(fixedRng("bc-b"))
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("bob".getBytes("UTF-8")) -> PeerCatalog.Peer(bPk, 2L),
    ))
    val alice = SiidaClient.create("alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog)
    val bob   = SiidaClient.create("bob".getBytes("UTF-8"),   bSk, bPk, 2L, mixPks, catalog)
    val onion = alice.sendChatMessage("bob".getBytes("UTF-8"), "plain".getBytes("UTF-8"), fixedRng("bc-snd")).toOption.get
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x22.toByte))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    val envBytes = MixChain.serialiseEnvelope(result.deliveries.head)
    val incoming = bob.deliver(envBytes).toOption.get
    incoming match
      case SiidaClient.IncomingMessage.ChatMessage(p) =>
        assertEquals(p.toSeq, "plain".getBytes("UTF-8").toSeq)
      case other => fail(s"expected ChatMessage, got $other")
  }
