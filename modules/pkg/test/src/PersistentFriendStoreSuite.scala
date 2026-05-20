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

import java.nio.file.{Files, Path}
import java.security.SecureRandom
import munit.FunSuite
import siida.crypto.api.HybridOnion
import siida.pkg.api.FriendStore

/** Spec 020 US3 — Persistent FriendStore survives restart. */
final class PersistentFriendStoreSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private def tmpPath(name: String): Path =
    Files.createTempFile(s"siida-fs-$name-", ".sifd")

  test("SC-003: add 3 friends, re-open at same path, list returns them in insertion order") {
    val path = tmpPath("restart")
    val store1 = FriendStore.persistent(path).toOption.get
    val (_, pa) = HybridOnion.generateBundle(fixedRng("pfs-a"))
    val (_, pb) = HybridOnion.generateBundle(fixedRng("pfs-b"))
    val (_, pc) = HybridOnion.generateBundle(fixedRng("pfs-c"))
    assertEquals(store1.add("alice".getBytes("UTF-8"), pa), true)
    assertEquals(store1.add("bob".getBytes("UTF-8"), pb), true)
    assertEquals(store1.add("carol".getBytes("UTF-8"), pc), true)

    // Open a second store backed by the same file (simulates a restart)
    val store2 = FriendStore.persistent(path).toOption.get
    val names = store2.list().map(new String(_, "UTF-8"))
    assertEquals(names, Vector("alice", "bob", "carol"))

    // Bundles round-trip
    val recoveredA = store2.lookup("alice".getBytes("UTF-8")).get
    assertEquals(
      HybridOnion.serialisePublicBundle(recoveredA).toSeq,
      HybridOnion.serialisePublicBundle(pa).toSeq)
  }

  test("idempotent re-add does NOT touch the file (returns false, original preserved)") {
    val path = tmpPath("idem")
    val store = FriendStore.persistent(path).toOption.get
    val (_, p1) = HybridOnion.generateBundle(fixedRng("idem-1"))
    val (_, p2) = HybridOnion.generateBundle(fixedRng("idem-2"))
    assertEquals(store.add("alice".getBytes("UTF-8"), p1), true)
    assertEquals(store.add("alice".getBytes("UTF-8"), p2), false)

    val store2 = FriendStore.persistent(path).toOption.get
    val found = store2.lookup("alice".getBytes("UTF-8")).get
    assertEquals(
      HybridOnion.serialisePublicBundle(found).toSeq,
      HybridOnion.serialisePublicBundle(p1).toSeq,
      "original bundle preserved after restart")
  }

  test("fresh store at a non-existent path opens cleanly") {
    val path = Files.createTempDirectory("siida-fresh-").resolve("a.sifd")
    val store = FriendStore.persistent(path).toOption.get
    assertEquals(store.list(), Vector.empty)
    assert(Files.exists(path), "store file must exist after construction")
  }

  test("corrupt file → load returns Left with explanation") {
    val path = tmpPath("corrupt")
    Files.write(path, Array[Byte](0x00, 0x00, 0x00, 0x00)) // bad magic
    val res = FriendStore.persistent(path)
    assert(res.isLeft, s"expected Left for corrupt file, got $res")
  }
