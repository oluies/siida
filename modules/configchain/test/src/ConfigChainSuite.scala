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

package siida.configchain

import java.security.SecureRandom
import munit.FunSuite
import siida.configchain.api.{ConfigChain, ConfigChainError, ConfigEntry}
import siida.crypto.api.{MultiSignedEntry, PqSignature}

final class ConfigChainSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private val dst = "siida/config-chain/v1/test".getBytes("UTF-8")

  /** Generate a 5-signer roster (sk, pk pairs) for the tests. */
  private def fiveSignerRoster(label: String): (Vector[PqSignature.PqPrivateKey], Vector[PqSignature.PqPublicKey]) =
    val pairs = (0 until 5).map(i => PqSignature.generateKeyPair(fixedRng(s"$label-r-$i"))).toVector
    (pairs.map(_._1), pairs.map(_._2))

  /** Build & sign a chained entry for the next epoch. Returns the
   *  MultiSignedEntry ready to feed into ConfigChain.append.
   *
   *  Caller can request a subset of signers via `signerIndices` for
   *  testing threshold-not-met cases.
   */
  private def buildNextEntry(
    chain:         ConfigChain,
    privs:         Vector[PqSignature.PqPrivateKey],
    newRoster:     Vector[PqSignature.PqPublicKey],
    newThreshold:  Int,
    signerIndices: Seq[Int],
    extension:     Array[Byte] = Array.emptyByteArray,
  ): MultiSignedEntry.Entry =
    val payload = ConfigEntry.encode(ConfigEntry(
      epoch        = chain.currentView.epoch + 1,
      prevHash     = chain.head,
      newRoster    = newRoster,
      newThreshold = newThreshold,
      extension    = extension,
    ))
    val msg = MultiSignedEntry.signedMessage(payload, dst)
    val sigs = signerIndices.map { i =>
      val sk = privs(i)
      (i, PqSignature.sign(sk, msg))
    }
    MultiSignedEntry.assemble(payload, sigs).toOption.get

  // ── US3: genesis bootstrap ─────────────────────────────────────

  test("genesis: builds a chain at epoch 0 with the declared roster + threshold") {
    val (_, pubs) = fiveSignerRoster("gen")
    val chain = ConfigChain.genesis(pubs, 3, dst).toOption.get
    assertEquals(chain.currentView.epoch, 0L)
    assertEquals(chain.currentView.threshold, 3)
    assertEquals(chain.currentView.roster.length, 5)
    assertEquals(chain.head.length, 32)
    assert(chain.at(0L).isDefined, "epoch 0 view must exist")
  }

  test("genesis rejects empty roster") {
    val res = ConfigChain.genesis(Vector.empty, 1, dst)
    assertEquals(res.left.toOption, Some(ConfigChainError.BadRoster("roster must be non-empty")))
  }

  test("genesis rejects out-of-range threshold") {
    val (_, pubs) = fiveSignerRoster("badth")
    val res = ConfigChain.genesis(pubs, 6, dst)
    assert(res.isLeft && res.left.toOption.get.isInstanceOf[ConfigChainError.BadThreshold],
      s"expected BadThreshold, got $res")
  }

  // ── US1: append happy path ─────────────────────────────────────

  test("append: 3-of-5 valid signers advance the chain head + view") {
    val (privs, pubs) = fiveSignerRoster("hp")
    val chain = ConfigChain.genesis(pubs, 3, dst).toOption.get
    val newRoster = pubs.updated(0, PqSignature.generateKeyPair(fixedRng("hp-new0"))._2)
    val entry = buildNextEntry(chain, privs, newRoster, newThreshold = 3, signerIndices = Seq(0, 1, 2))
    val view = chain.append(entry).toOption.get
    assertEquals(view.epoch, 1L)
    assertEquals(view.threshold, 3)
    assertEquals(view.roster.length, 5)
    assertEquals(chain.currentView.epoch, 1L)
    // The new roster slot 0 has been replaced
    assertNotEquals(
      PqSignature.serialisePublicKey(chain.currentView.roster(0)).toSeq,
      PqSignature.serialisePublicKey(pubs(0)).toSeq)
  }

  test("append: 2-of-5 signers → ThresholdNotMet") {
    val (privs, pubs) = fiveSignerRoster("tnm")
    val chain = ConfigChain.genesis(pubs, 3, dst).toOption.get
    val entry = buildNextEntry(chain, privs, pubs, 3, Seq(0, 1))
    val res = chain.append(entry)
    assert(res.isLeft && res.left.toOption.get.isInstanceOf[ConfigChainError.ThresholdNotMet],
      s"expected ThresholdNotMet, got $res")
  }

  // ── US2: replay / wrong predecessor ────────────────────────────

  test("append: wrong predecessor (prev_hash doesn't match head) → WrongPredecessor") {
    val (privs, pubs) = fiveSignerRoster("wp")
    val chain = ConfigChain.genesis(pubs, 3, dst).toOption.get
    // Build an entry whose prev_hash is the all-zero hash, not the
    // genesis hash.
    val payload = ConfigEntry.encode(ConfigEntry(
      epoch = 1L,
      prevHash = new Array[Byte](32),
      newRoster = pubs,
      newThreshold = 3,
      extension = Array.emptyByteArray,
    ))
    val msg = MultiSignedEntry.signedMessage(payload, dst)
    val sigs = Seq(0, 1, 2).map(i => (i, PqSignature.sign(privs(i), msg)))
    val entry = MultiSignedEntry.assemble(payload, sigs).toOption.get
    val res = chain.append(entry)
    assertEquals(res, Left(ConfigChainError.WrongPredecessor))
  }

  test("append: replay of an already-applied entry → AlreadyApplied") {
    val (privs, pubs) = fiveSignerRoster("rep")
    val chain = ConfigChain.genesis(pubs, 3, dst).toOption.get
    val entry = buildNextEntry(chain, privs, pubs, 3, Seq(0, 1, 2))
    chain.append(entry).toOption.get
    val again = chain.append(entry)
    assertEquals(again, Left(ConfigChainError.AlreadyApplied))
  }

  test("append: non-monotonic epoch (skipping 1 to go to 2) → EpochNotMonotonic") {
    val (privs, pubs) = fiveSignerRoster("ep")
    val chain = ConfigChain.genesis(pubs, 3, dst).toOption.get
    val payload = ConfigEntry.encode(ConfigEntry(
      epoch = 2L,    // SKIP — should be 1
      prevHash = chain.head,
      newRoster = pubs,
      newThreshold = 3,
      extension = Array.emptyByteArray,
    ))
    val msg = MultiSignedEntry.signedMessage(payload, dst)
    val sigs = Seq(0, 1, 2).map(i => (i, PqSignature.sign(privs(i), msg)))
    val entry = MultiSignedEntry.assemble(payload, sigs).toOption.get
    val res = chain.append(entry)
    res match
      case Left(ConfigChainError.EpochNotMonotonic(1L, 2L)) => ()
      case other => fail(s"expected EpochNotMonotonic(1, 2), got $other")
  }

  // ── New roster sanity checks at append-time ────────────────────

  test("append rejects new entry that declares empty new_roster") {
    val (privs, pubs) = fiveSignerRoster("nr")
    val chain = ConfigChain.genesis(pubs, 3, dst).toOption.get
    val entry = buildNextEntry(chain, privs, Vector.empty, 0, Seq(0, 1, 2))
    val res = chain.append(entry)
    assert(res.isLeft && res.left.toOption.get.isInstanceOf[ConfigChainError.BadRoster],
      s"expected BadRoster, got $res")
  }

  test("append rejects new entry with new_threshold > new_roster.length") {
    val (privs, pubs) = fiveSignerRoster("bt")
    val chain = ConfigChain.genesis(pubs, 3, dst).toOption.get
    val entry = buildNextEntry(chain, privs, pubs, newThreshold = 99, signerIndices = Seq(0, 1, 2))
    val res = chain.append(entry)
    assert(res.isLeft && res.left.toOption.get.isInstanceOf[ConfigChainError.BadThreshold],
      s"expected BadThreshold, got $res")
  }

  // ── Multi-entry application advances epoch correctly ───────────

  test("multi-append: chain epoch advances 0 → 1 → 2 → 3 with valid quorums") {
    val (privs, pubs) = fiveSignerRoster("multi")
    val chain = ConfigChain.genesis(pubs, 3, dst).toOption.get
    (1 to 3).foreach { _ =>
      val entry = buildNextEntry(chain, privs, pubs, 3, Seq(0, 2, 4))
      chain.append(entry).toOption.get
    }
    assertEquals(chain.currentView.epoch, 3L)
    assertEquals(chain.history.length, 4) // genesis + 3 applied
    assert(chain.at(0L).isDefined && chain.at(1L).isDefined && chain.at(2L).isDefined && chain.at(3L).isDefined)
    assertEquals(chain.at(99L), None)
  }
