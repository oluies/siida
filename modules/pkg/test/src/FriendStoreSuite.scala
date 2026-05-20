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
import siida.pkg.api.FriendStore

/** Spec 019 — FriendStore in-memory semantics. */
final class FriendStoreSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  test("empty store: lookup returns None, list returns empty") {
    val store = FriendStore.inMemory()
    assertEquals(store.lookup("alice".getBytes("UTF-8")), None)
    assertEquals(store.list(), Vector.empty)
  }

  test("add → lookup recovers the bundle") {
    val store = FriendStore.inMemory()
    val (_, public) = HybridOnion.generateBundle(fixedRng("fs-alice"))
    assertEquals(store.add("alice".getBytes("UTF-8"), public), true)
    val found = store.lookup("alice".getBytes("UTF-8"))
    assert(found.isDefined, "expected to find alice")
    assertEquals(
      HybridOnion.serialisePublicBundle(found.get).toSeq,
      HybridOnion.serialisePublicBundle(public).toSeq)
  }

  test("re-adding the same identity returns false (idempotent), does not replace the bundle") {
    val store = FriendStore.inMemory()
    val (_, public1) = HybridOnion.generateBundle(fixedRng("idem-1"))
    val (_, public2) = HybridOnion.generateBundle(fixedRng("idem-2"))
    assertEquals(store.add("alice".getBytes("UTF-8"), public1), true)
    assertEquals(store.add("alice".getBytes("UTF-8"), public2), false,
      "second add must return false")
    val found = store.lookup("alice".getBytes("UTF-8")).get
    assertEquals(
      HybridOnion.serialisePublicBundle(found).toSeq,
      HybridOnion.serialisePublicBundle(public1).toSeq,
      "original bundle must be preserved (not replaced)")
  }

  test("list returns identities in insertion order") {
    val store = FriendStore.inMemory()
    val (_, pa) = HybridOnion.generateBundle(fixedRng("order-a"))
    val (_, pb) = HybridOnion.generateBundle(fixedRng("order-b"))
    val (_, pc) = HybridOnion.generateBundle(fixedRng("order-c"))
    store.add("alice".getBytes("UTF-8"), pa)
    store.add("bob".getBytes("UTF-8"), pb)
    store.add("carol".getBytes("UTF-8"), pc)
    val listed = store.list().map(new String(_, "UTF-8"))
    assertEquals(listed, Vector("alice", "bob", "carol"))
  }

  test("lookup uses structural identity equality (different array, same bytes)") {
    val store = FriendStore.inMemory()
    val (_, public) = HybridOnion.generateBundle(fixedRng("eq-bundle"))
    store.add("alice".getBytes("UTF-8"), public)
    // Build a fresh array with the same bytes
    val alice2: Array[Byte] = "alice".getBytes("UTF-8")
    val found = store.lookup(alice2)
    assert(found.isDefined, "expected structural lookup to find alice")
  }
