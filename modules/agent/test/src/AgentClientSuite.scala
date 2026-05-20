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

package siida.agent

import java.security.SecureRandom
import munit.FunSuite
import siida.agent.api.AgentClient
import siida.crypto.api.HybridOnion
import siida.mixnet.api.{Coordinator, MixChain}
import siida.sdk.api.{PeerCatalog, SiidaClient}

final class AgentClientSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private def mkMixChain(label: String): (Vector[HybridOnion.HybridSecretBundle], Vector[HybridOnion.HybridPublicBundle]) =
    val pairs = (0 until 2).map(i => HybridOnion.generateBundle(fixedRng(s"$label-mix-$i"))).toVector
    (pairs.map(_._1), pairs.map(_._2))

  private def runOneRound(
    mixSks:  Vector[HybridOnion.HybridSecretBundle],
    onion:   HybridOnion.OnionLayer,
    seedTag: String,
  ): Array[Byte] =
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x42.toByte))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    assertEquals(result.deliveries.length, 1)
    val _ = seedTag
    MixChain.serialiseEnvelope(result.deliveries.head)

  test("SC-001: request → response round-trip via the mixnet") {
    val (mixSks, mixPks) = mkMixChain("req")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("req-a"))
    val (bSk, bPk) = HybridOnion.generateBundle(fixedRng("req-b"))

    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("alice".getBytes("UTF-8")) -> PeerCatalog.Peer(aPk, 1L),
      IArray.unsafeFromArray("bob".getBytes("UTF-8"))   -> PeerCatalog.Peer(bPk, 2L),
    ))
    val a = AgentClient.from(SiidaClient.create("alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog))
    val b = AgentClient.from(SiidaClient.create("bob".getBytes("UTF-8"),   bSk, bPk, 2L, mixPks, catalog))

    // alice → bob request
    val (onionReq, rid) = a.sendRequest("bob".getBytes("UTF-8"), "ping".getBytes("UTF-8"), fixedRng("req-snd")).toOption.get
    val envBytes = runOneRound(mixSks, onionReq, "req-1")
    val recvd = b.deliverAgent(envBytes).toOption.get
    recvd match
      case AgentClient.AgentIncoming.Request(rrid, content) =>
        assertEquals(rrid.toSeq, rid.toSeq)
        assertEquals(content.toSeq, "ping".getBytes("UTF-8").toSeq)
      case other => fail(s"expected Request, got $other")

    // bob → alice response, echoing rid
    val onionRsp = b.sendResponse("alice".getBytes("UTF-8"), rid, "pong".getBytes("UTF-8"), fixedRng("req-rsp")).toOption.get
    val envBytes2 = runOneRound(mixSks, onionRsp, "req-2")
    val recvd2 = a.deliverAgent(envBytes2).toOption.get
    recvd2 match
      case AgentClient.AgentIncoming.Response(rrid, content) =>
        assertEquals(rrid.toSeq, rid.toSeq)
        assertEquals(content.toSeq, "pong".getBytes("UTF-8").toSeq)
      case other => fail(s"expected Response, got $other")
  }

  test("SC-002: raw chat (no SIAG prefix) → AgentIncoming.RawChat") {
    val (mixSks, mixPks) = mkMixChain("raw")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("raw-a"))
    val (bSk, bPk) = HybridOnion.generateBundle(fixedRng("raw-b"))
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("alice".getBytes("UTF-8")) -> PeerCatalog.Peer(aPk, 1L),
      IArray.unsafeFromArray("bob".getBytes("UTF-8"))   -> PeerCatalog.Peer(bPk, 2L),
    ))
    val alice = SiidaClient.create("alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog)
    val b = AgentClient.from(SiidaClient.create("bob".getBytes("UTF-8"), bSk, bPk, 2L, mixPks, catalog))

    val onion = alice.sendChatMessage("bob".getBytes("UTF-8"), Array[Byte](0x42), fixedRng("raw-snd")).toOption.get
    val envBytes = runOneRound(mixSks, onion, "raw")
    val recvd = b.deliverAgent(envBytes).toOption.get
    recvd match
      case AgentClient.AgentIncoming.RawChat(p) =>
        assertEquals(p.toSeq, Seq[Byte](0x42))
      case other => fail(s"expected RawChat, got $other")
  }

  test("SC-003: notification round-trip with zero request id") {
    val (mixSks, mixPks) = mkMixChain("not")
    val (aSk, aPk) = HybridOnion.generateBundle(fixedRng("not-a"))
    val (bSk, bPk) = HybridOnion.generateBundle(fixedRng("not-b"))
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("alice".getBytes("UTF-8")) -> PeerCatalog.Peer(aPk, 1L),
      IArray.unsafeFromArray("bob".getBytes("UTF-8"))   -> PeerCatalog.Peer(bPk, 2L),
    ))
    val a = AgentClient.from(SiidaClient.create("alice".getBytes("UTF-8"), aSk, aPk, 1L, mixPks, catalog))
    val b = AgentClient.from(SiidaClient.create("bob".getBytes("UTF-8"),   bSk, bPk, 2L, mixPks, catalog))

    val onion = a.sendNotification("bob".getBytes("UTF-8"), "hi".getBytes("UTF-8"), fixedRng("not-snd")).toOption.get
    val envBytes = runOneRound(mixSks, onion, "not")
    val recvd = b.deliverAgent(envBytes).toOption.get
    recvd match
      case AgentClient.AgentIncoming.Notification(content) =>
        assertEquals(content.toSeq, "hi".getBytes("UTF-8").toSeq)
      case other => fail(s"expected Notification, got $other")
  }
