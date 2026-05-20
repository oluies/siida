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
import siida.crypto.api.{HybridOnion, PqSignature}
import siida.pkg.api.{Friendship, FriendshipError, Pkg}

/** Spec 019 — Friendship.buildAddRequest + processAddRequest +
 *  verifyAddRequest happy paths and forgery rejection.
 */
final class FriendshipSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private val dst = "siida/test/v1/friend-discovery".getBytes("UTF-8")

  /** Build a 3-of-5 PKG roster + a PKG instance. */
  private def pkgWithRoster(): Pkg =
    val pairs = (0 until 5).map(i => PqSignature.generateKeyPair(fixedRng(s"fr-roster-$i")))
    val pubs = pairs.map(_._2)
    val privs = pairs.map(_._1)
    Pkg.create(pubs, privs, 3, dst).toOption.get

  // ── US1 happy path ─────────────────────────────────────────────

  test("alice → bob: buildAddRequest → processAddRequest recovers alice's identity + public bundle (SC-001)") {
    val pkg = pkgWithRoster()
    val alice = pkg.issueIdentity("alice@siida".getBytes("UTF-8"), fixedRng("fr-alice")).toOption.get
    val bob   = pkg.issueIdentity("bob@siida".getBytes("UTF-8"),   fixedRng("fr-bob")).toOption.get

    val req = Friendship.buildAddRequest(
      "alice@siida".getBytes("UTF-8"),
      alice.publicBundle,
      bob.publicBundle,
      fixedRng("fr-build"),
    )

    val content = Friendship.processAddRequest(bob.secretBundle, req).toOption.get
    assertEquals(content.senderIdentity.toSeq, "alice@siida".getBytes("UTF-8").toSeq)
    assertEquals(
      HybridOnion.serialisePublicBundle(content.senderPublicBundle).toSeq,
      HybridOnion.serialisePublicBundle(alice.publicBundle).toSeq)
  }

  test("verifyAddRequest succeeds when the claim matches the directory binding (SC-001)") {
    val pkg = pkgWithRoster()
    val alice = pkg.issueIdentity("alice@siida".getBytes("UTF-8"), fixedRng("vr-alice")).toOption.get
    val bob   = pkg.issueIdentity("bob@siida".getBytes("UTF-8"),   fixedRng("vr-bob")).toOption.get

    val directory = pkg.directorySnapshot()
    val req = Friendship.buildAddRequest(
      "alice@siida".getBytes("UTF-8"),
      alice.publicBundle,
      bob.publicBundle,
      fixedRng("vr-build"),
    )
    val content = Friendship.processAddRequest(bob.secretBundle, req).toOption.get
    val verified = Friendship.verifyAddRequest(content, directory)
    assertEquals(verified, Right(()))
  }

  // ── US2 forgery rejection ──────────────────────────────────────

  test("forgery: carol claims to be alice but uses her own public bundle → IdentityMismatch (SC-002)") {
    val pkg = pkgWithRoster()
    // Issue alice so the directory contains her legitimate binding;
    // the test's verifyAddRequest path needs the directory to know
    // about alice in order to detect the bundle mismatch.
    val _ = pkg.issueIdentity("alice@siida".getBytes("UTF-8"), fixedRng("forge-alice")).toOption.get
    val bob   = pkg.issueIdentity("bob@siida".getBytes("UTF-8"),   fixedRng("forge-bob")).toOption.get
    val carol = pkg.issueIdentity("carol@siida".getBytes("UTF-8"), fixedRng("forge-carol")).toOption.get

    val directory = pkg.directorySnapshot()
    // Carol builds a request CLAIMING to be alice (using alice's
    // identity string) but with HER OWN public bundle inside.
    val forgedReq = Friendship.buildAddRequest(
      "alice@siida".getBytes("UTF-8"),
      carol.publicBundle,    // ← FORGERY: carol's bundle, not alice's
      bob.publicBundle,
      fixedRng("forge-build"),
    )

    // Bob decrypts successfully — the ciphertext is well-formed
    // and addressed to him
    val content = Friendship.processAddRequest(bob.secretBundle, forgedReq).toOption.get
    assertEquals(content.senderIdentity.toSeq, "alice@siida".getBytes("UTF-8").toSeq)

    // …but verification FAILS because alice's directory binding
    // points to alice's bundle, not carol's
    val verified = Friendship.verifyAddRequest(content, directory)
    assertEquals(verified, Left(FriendshipError.IdentityMismatch))
  }

  test("unknown sender (not in directory) → IdentityNotInDirectory") {
    val pkg = pkgWithRoster()
    val (aliceSecret, alicePublic) = HybridOnion.generateBundle(fixedRng("ghost-alice-bundle"))
    val bob = pkg.issueIdentity("bob@siida".getBytes("UTF-8"), fixedRng("ghost-bob")).toOption.get

    val directory = pkg.directorySnapshot()
    val req = Friendship.buildAddRequest(
      "ghost@siida".getBytes("UTF-8"),
      alicePublic,
      bob.publicBundle,
      fixedRng("ghost-build"),
    )
    val content = Friendship.processAddRequest(bob.secretBundle, req).toOption.get
    val verified = Friendship.verifyAddRequest(content, directory)
    assertEquals(verified, Left(FriendshipError.IdentityNotInDirectory))
  }

  // ── Tamper rejection ───────────────────────────────────────────

  test("tampered ciphertext → DecryptionFailed (SC-003)") {
    val pkg = pkgWithRoster()
    val alice = pkg.issueIdentity("alice@siida".getBytes("UTF-8"), fixedRng("tamp-alice")).toOption.get
    val bob   = pkg.issueIdentity("bob@siida".getBytes("UTF-8"),   fixedRng("tamp-bob")).toOption.get

    val req = Friendship.buildAddRequest(
      "alice@siida".getBytes("UTF-8"),
      alice.publicBundle,
      bob.publicBundle,
      fixedRng("tamp-build"),
    )
    val bytes = Friendship.serialiseAddRequest(req)
    // Flip the last byte (AEAD tag region)
    bytes(bytes.length - 1) = (bytes(bytes.length - 1) ^ 0x01).toByte
    val tampered = Friendship.deserialiseAddRequest(bytes).toOption.get
    val res = Friendship.processAddRequest(bob.secretBundle, tampered)
    assertEquals(res, Left(FriendshipError.DecryptionFailed))
  }

  // ── Alg-ID uniform refusal (SC-004) ────────────────────────────

  test("deserialiseAddRequest rejects unknown alg-ID uniformly (FR-007)") {
    val pkg = pkgWithRoster()
    val alice = pkg.issueIdentity("alice@siida".getBytes("UTF-8"), fixedRng("alg-alice")).toOption.get
    val bob   = pkg.issueIdentity("bob@siida".getBytes("UTF-8"),   fixedRng("alg-bob")).toOption.get
    val req = Friendship.buildAddRequest(
      "alice@siida".getBytes("UTF-8"),
      alice.publicBundle, bob.publicBundle,
      fixedRng("alg-build"),
    )
    val bytes = Friendship.serialiseAddRequest(req)
    bytes(0) = 0x42.toByte
    val res = Friendship.deserialiseAddRequest(bytes)
    assertEquals(res, Left(FriendshipError.UnsupportedAlgorithm))
  }

  test("deserialiseAddRequest rejects too-short input with InvalidLength") {
    val res = Friendship.deserialiseAddRequest(new Array[Byte](50))
    assertEquals(res, Left(FriendshipError.InvalidLength))
  }

  // ── Wire-format size sanity ────────────────────────────────────

  test("AddRequest wire size = 1 (alg) + 1137 (onion) + 1218 + identity_len (inner payload)") {
    val pkg = pkgWithRoster()
    val alice = pkg.issueIdentity("alice".getBytes("UTF-8"), fixedRng("sz-alice")).toOption.get
    val bob   = pkg.issueIdentity("bob".getBytes("UTF-8"),   fixedRng("sz-bob")).toOption.get
    val req = Friendship.buildAddRequest(
      "alice".getBytes("UTF-8"),
      alice.publicBundle,
      bob.publicBundle,
      fixedRng("sz-build"),
    )
    val bytes = Friendship.serialiseAddRequest(req)
    val expected = 1 + 1137 + 1218 + "alice".length // 5 byte identity
    assertEquals(bytes.length, expected)
  }
