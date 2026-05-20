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

package siida.pkg

import java.security.SecureRandom
import munit.FunSuite
import siida.crypto.api.HybridOnion
import siida.pkg.api.Friendship

/** Spec 020 US2 — Friendship-key derivation symmetry + determinism. */
final class FriendshipKeySuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  test("SC-002 symmetry: deriveFriendshipKey(a, b, id) == deriveFriendshipKey(b, a, id)") {
    val (_, a) = HybridOnion.generateBundle(fixedRng("sym-a"))
    val (_, b) = HybridOnion.generateBundle(fixedRng("sym-b"))
    val id = "discovery-1".getBytes("UTF-8")
    val ka = Friendship.deriveFriendshipKey(a, b, id)
    val kb = Friendship.deriveFriendshipKey(b, a, id)
    assertEquals(ka.toSeq, kb.toSeq)
    assertEquals(ka.length, 32)
  }

  test("determinism: two derivations with the same inputs return the same key") {
    val (_, a) = HybridOnion.generateBundle(fixedRng("det-a"))
    val (_, b) = HybridOnion.generateBundle(fixedRng("det-b"))
    val id = "ad1".getBytes("UTF-8")
    val k1 = Friendship.deriveFriendshipKey(a, b, id)
    val k2 = Friendship.deriveFriendshipKey(a, b, id)
    assertEquals(k1.toSeq, k2.toSeq)
  }

  test("different adIds → different keys for the same pair") {
    val (_, a) = HybridOnion.generateBundle(fixedRng("dad-a"))
    val (_, b) = HybridOnion.generateBundle(fixedRng("dad-b"))
    val k1 = Friendship.deriveFriendshipKey(a, b, "id1".getBytes("UTF-8"))
    val k2 = Friendship.deriveFriendshipKey(a, b, "id2".getBytes("UTF-8"))
    assertNotEquals(k1.toSeq, k2.toSeq)
  }

  test("different pair → different key for the same adId") {
    val (_, a) = HybridOnion.generateBundle(fixedRng("dp-a"))
    val (_, b) = HybridOnion.generateBundle(fixedRng("dp-b"))
    val (_, c) = HybridOnion.generateBundle(fixedRng("dp-c"))
    val id = "x".getBytes("UTF-8")
    val k1 = Friendship.deriveFriendshipKey(a, b, id)
    val k2 = Friendship.deriveFriendshipKey(a, c, id)
    assertNotEquals(k1.toSeq, k2.toSeq)
  }
