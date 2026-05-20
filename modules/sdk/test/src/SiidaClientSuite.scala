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
import siida.sdk.api.{PeerCatalog, SdkError, SiidaClient}

final class SiidaClientSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  /** Build a 2-hop mix chain of hybrid bundles. */
  private def mkMixChain(label: String): (Vector[HybridOnion.HybridSecretBundle], Vector[HybridOnion.HybridPublicBundle]) =
    val pairs = (0 until 2).map(i => HybridOnion.generateBundle(fixedRng(s"$label-mix-$i"))).toVector
    (pairs.map(_._1), pairs.map(_._2))

  /** Pre-verified peer catalog wired around (identity → (bundle, mailboxId)). */
  private def mkCatalog(peers: Seq[(Array[Byte], HybridOnion.HybridPublicBundle, Long)]): PeerCatalog =
    val entries = peers.map { (id, pub, mid) =>
      IArray.unsafeFromArray(id.clone()) -> PeerCatalog.Peer(pub, mid)
    }.toMap
    PeerCatalog.inMemoryVerified(entries)

  test("SC-001: alice → bob chat round-trips through the mixnet") {
    val (mixSks, mixPks) = mkMixChain("chat")
    val (aliceSk, alicePk) = HybridOnion.generateBundle(fixedRng("chat-alice"))
    val (bobSk, bobPk)     = HybridOnion.generateBundle(fixedRng("chat-bob"))

    val catalog = mkCatalog(Seq(
      ("bob".getBytes("UTF-8"),   bobPk,   2L),
      ("alice".getBytes("UTF-8"), alicePk, 1L),
    ))

    val alice = SiidaClient.create("alice".getBytes("UTF-8"), aliceSk, alicePk, 1L, mixPks, catalog)
    val bob   = SiidaClient.create("bob".getBytes("UTF-8"),   bobSk,   bobPk,   2L, mixPks, catalog)

    val payload = "hello bob, this is alice".getBytes("UTF-8")
    val onion = alice.sendChatMessage("bob".getBytes("UTF-8"), payload, fixedRng("chat-send")).toOption.get

    // Run one mixnet round with alice's submission
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x00.toByte))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    assertEquals(result.deliveries.length, 1)

    // Bob picks up his envelope and delivers
    val bobEnvBytes = MixChain.serialiseEnvelope(result.deliveries.head)
    val incoming = bob.deliver(bobEnvBytes).toOption.get
    incoming match
      case SiidaClient.IncomingMessage.ChatMessage(p) =>
        assertEquals(p.toSeq, payload.toSeq)
      case other => fail(s"expected ChatMessage, got $other")
  }

  test("SC-002: alice → bob add-request round-trips") {
    val (mixSks, mixPks) = mkMixChain("ar")
    val (aliceSk, alicePk) = HybridOnion.generateBundle(fixedRng("ar-alice"))
    val (bobSk, bobPk)     = HybridOnion.generateBundle(fixedRng("ar-bob"))

    val catalog = mkCatalog(Seq(
      ("bob".getBytes("UTF-8"),   bobPk,   2L),
      ("alice".getBytes("UTF-8"), alicePk, 1L),
    ))
    val alice = SiidaClient.create("alice".getBytes("UTF-8"), aliceSk, alicePk, 1L, mixPks, catalog)
    val bob   = SiidaClient.create("bob".getBytes("UTF-8"),   bobSk,   bobPk,   2L, mixPks, catalog)

    val onion = alice.sendAddRequest("bob".getBytes("UTF-8"), fixedRng("ar-send")).toOption.get
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x77.toByte))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    assertEquals(result.deliveries.length, 1)

    val bobEnvBytes = MixChain.serialiseEnvelope(result.deliveries.head)
    val incoming = bob.deliver(bobEnvBytes).toOption.get
    incoming match
      case SiidaClient.IncomingMessage.AddRequest(content) =>
        assertEquals(content.senderIdentity.toSeq, "alice".getBytes("UTF-8").toSeq)
        assertEquals(
          HybridOnion.serialisePublicBundle(content.senderPublicBundle).toSeq,
          HybridOnion.serialisePublicBundle(alicePk).toSeq)
      case other => fail(s"expected AddRequest, got $other")
  }

  test("send to unknown identity → IdentityNotInDirectory") {
    val (_, mixPks) = mkMixChain("uk")
    val (sk, pk) = HybridOnion.generateBundle(fixedRng("uk-alice"))
    val catalog = mkCatalog(Seq.empty)
    val client = SiidaClient.create("alice".getBytes("UTF-8"), sk, pk, 1L, mixPks, catalog)
    val res = client.sendChatMessage("nobody".getBytes("UTF-8"), Array.emptyByteArray, fixedRng("uk-send"))
    assertEquals(res, Left(SdkError.IdentityNotInDirectory))
  }

  test("deliver: envelope addressed to a different mailbox → WrongMailbox") {
    val (mixSks, mixPks) = mkMixChain("wm")
    val (aliceSk, alicePk) = HybridOnion.generateBundle(fixedRng("wm-alice"))
    val (bobSk, bobPk)     = HybridOnion.generateBundle(fixedRng("wm-bob"))
    val (carolSk, carolPk) = HybridOnion.generateBundle(fixedRng("wm-carol"))

    val catalog = mkCatalog(Seq(
      ("bob".getBytes("UTF-8"),   bobPk,   2L),
      ("carol".getBytes("UTF-8"), carolPk, 3L),
    ))
    val alice = SiidaClient.create("alice".getBytes("UTF-8"), aliceSk, alicePk, 1L, mixPks, catalog)
    val carol = SiidaClient.create("carol".getBytes("UTF-8"), carolSk, carolPk, 3L, mixPks, catalog)
    val _ = bobSk

    val onion = alice.sendChatMessage("bob".getBytes("UTF-8"), "for bob".getBytes("UTF-8"), fixedRng("wm-send")).toOption.get
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x11.toByte))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    // Carol tries to deliver the envelope addressed to bob's mailbox
    val envBytes = MixChain.serialiseEnvelope(result.deliveries.head)
    val res = carol.deliver(envBytes)
    assertEquals(res, Left(SdkError.WrongMailbox))
  }

  test("SC-003: tampered envelope payload → DecryptionFailed") {
    val (mixSks, mixPks) = mkMixChain("tamp")
    val (aliceSk, alicePk) = HybridOnion.generateBundle(fixedRng("tamp-alice"))
    val (bobSk, bobPk)     = HybridOnion.generateBundle(fixedRng("tamp-bob"))

    val catalog = mkCatalog(Seq(
      ("bob".getBytes("UTF-8"), bobPk, 2L),
    ))
    val alice = SiidaClient.create("alice".getBytes("UTF-8"), aliceSk, alicePk, 1L, mixPks, catalog)
    val bob   = SiidaClient.create("bob".getBytes("UTF-8"),   bobSk,   bobPk,   2L, mixPks, catalog)

    val onion = alice.sendChatMessage("bob".getBytes("UTF-8"), "hi".getBytes("UTF-8"), fixedRng("tamp-send")).toOption.get
    val seeds = Vector.fill(mixSks.length)(Array.fill[Byte](32)(0x33.toByte))
    val result = Coordinator.runRound(Vector(onion), mixSks, seeds)
    val envBytes = MixChain.serialiseEnvelope(result.deliveries.head)
    // Flip a byte deep in the inner SDK payload (well past the
    // mailbox id header) to corrupt the e2e ciphertext
    envBytes(envBytes.length - 1) = (envBytes(envBytes.length - 1) ^ 0x01).toByte
    val res = bob.deliver(envBytes)
    assertEquals(res, Left(SdkError.DecryptionFailed))
  }

  test("SC-005: cover submission with the right inner-payload size yields same outermost wire length as a real submission") {
    val (_, mixPks) = mkMixChain("cov")
    val (sk, pk) = HybridOnion.generateBundle(fixedRng("cov-alice"))
    val (_, peerPk) = HybridOnion.generateBundle(fixedRng("cov-peer"))
    val catalog = mkCatalog(Seq(("peer".getBytes("UTF-8"), peerPk, 5L)))
    val alice = SiidaClient.create("alice".getBytes("UTF-8"), sk, pk, 1L, mixPks, catalog)

    val payload = Array.fill[Byte](64)(0x42.toByte)
    val real = alice.sendChatMessage("peer".getBytes("UTF-8"), payload, fixedRng("cov-real")).toOption.get

    // The "inner payload" inside the MailboxEnvelope is the SDK-wrapped
    // e2e ciphertext: 1 byte SDK type + serialised OnionLayer bytes.
    val e2e = HybridOnion.encrypt(peerPk, payload, fixedRng("cov-e2e-size"))
    val innerLen = 1 + HybridOnion.serialiseLayer(e2e).length
    val cover = alice.coverSubmission(innerLen, fixedRng("cov-fake"))
    assertEquals(HybridOnion.serialiseLayer(cover).length,
                 HybridOnion.serialiseLayer(real).length,
                 "cover and real submissions must produce the same outermost wire length for the same inner-payload size")
  }

  test("unknown SDK type byte → UnsupportedSdkType") {
    val (mixSks, mixPks) = mkMixChain("ut")
    val (bobSk, bobPk) = HybridOnion.generateBundle(fixedRng("ut-bob"))
    val catalog = mkCatalog(Seq.empty)
    val bob = SiidaClient.create("bob".getBytes("UTF-8"), bobSk, bobPk, 2L, mixPks, catalog)
    val _ = mixSks

    // Hand-craft a delivered envelope with unsupported SDK type
    val sdkInner = Array.ofDim[Byte](10)
    sdkInner(0) = 0x99.toByte // unsupported
    val env = MixChain.envelope(2L, sdkInner)
    val res = bob.deliver(MixChain.serialiseEnvelope(env))
    assertEquals(res, Left(SdkError.UnsupportedSdkType))
  }
