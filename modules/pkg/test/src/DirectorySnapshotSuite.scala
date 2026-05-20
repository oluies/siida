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
import siida.crypto.api.{IdentityEncryption, IdentityEncError, PqSignature}
import siida.pkg.api.{Pkg, DirectoryEntryWire}

/** Spec 005 US3 — directorySnapshot composes with 015's
 *  IdentityEncryption end-to-end.
 */
final class DirectorySnapshotSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private val dst = "siida/test/v1/pkg-005-snapshot".getBytes("UTF-8")

  private def roster(): (Seq[PqSignature.PqPublicKey], Seq[PqSignature.PqPrivateKey]) =
    val pairs = (0 until 5).map(i => PqSignature.generateKeyPair(fixedRng(s"snap-roster-$i")))
    (pairs.map(_._2), pairs.map(_._1))

  test("issue 3 identities, sender encrypts to each, recipient decrypts (SC-001)") {
    val (pubs, privs) = roster()
    val pkg = Pkg.create(pubs, privs, 3, dst).toOption.get

    val alice = pkg.issueIdentity("alice@siida".getBytes("UTF-8"), fixedRng("snap-alice")).toOption.get
    val bob   = pkg.issueIdentity("bob@siida".getBytes("UTF-8"),   fixedRng("snap-bob")).toOption.get
    val carol = pkg.issueIdentity("carol@siida".getBytes("UTF-8"), fixedRng("snap-carol")).toOption.get

    val directory = pkg.directorySnapshot()

    // Sender encrypts to alice, alice decrypts
    val ctAlice = IdentityEncryption.encrypt(
      directory, "alice@siida".getBytes("UTF-8"),
      "msg-for-alice".getBytes("UTF-8"),
      fixedRng("snap-enc-alice"),
    ).toOption.get
    val recoveredAlice = IdentityEncryption.decrypt(alice.secretBundle, ctAlice).toOption.get
    assertEquals(recoveredAlice.toSeq, "msg-for-alice".getBytes("UTF-8").toSeq)

    // bob
    val ctBob = IdentityEncryption.encrypt(
      directory, "bob@siida".getBytes("UTF-8"),
      "msg-for-bob".getBytes("UTF-8"),
      fixedRng("snap-enc-bob"),
    ).toOption.get
    val recoveredBob = IdentityEncryption.decrypt(bob.secretBundle, ctBob).toOption.get
    assertEquals(recoveredBob.toSeq, "msg-for-bob".getBytes("UTF-8").toSeq)

    // carol
    val ctCarol = IdentityEncryption.encrypt(
      directory, "carol@siida".getBytes("UTF-8"),
      "msg-for-carol".getBytes("UTF-8"),
      fixedRng("snap-enc-carol"),
    ).toOption.get
    val recoveredCarol = IdentityEncryption.decrypt(carol.secretBundle, ctCarol).toOption.get
    assertEquals(recoveredCarol.toSeq, "msg-for-carol".getBytes("UTF-8").toSeq)
  }

  test("snapshot lookup for an unknown identity → IdentityNotFound") {
    val (pubs, privs) = roster()
    val pkg = Pkg.create(pubs, privs, 3, dst).toOption.get
    pkg.issueIdentity("alice".getBytes("UTF-8"), fixedRng("snap-miss")).toOption.get

    val directory = pkg.directorySnapshot()
    val res = IdentityEncryption.encrypt(
      directory, "ghost".getBytes("UTF-8"),
      "doomed".getBytes("UTF-8"),
      fixedRng("snap-ghost"),
    )
    assertEquals(res, Left(IdentityEncError.IdentityNotFound))
  }

  test("snapshot taken before issuing bob does NOT include bob") {
    val (pubs, privs) = roster()
    val pkg = Pkg.create(pubs, privs, 3, dst).toOption.get
    pkg.issueIdentity("alice".getBytes("UTF-8"), fixedRng("snap-pre-alice")).toOption.get
    val snapshotBefore = pkg.directorySnapshot()

    // Bob is issued AFTER the snapshot
    pkg.issueIdentity("bob".getBytes("UTF-8"), fixedRng("snap-pre-bob")).toOption.get

    // Looking bob up in the *earlier* snapshot fails — snapshot
    // is frozen at the time of the call
    val res = IdentityEncryption.encrypt(
      snapshotBefore, "bob".getBytes("UTF-8"),
      "should-fail".getBytes("UTF-8"),
      fixedRng("snap-bob-encrypt"),
    )
    assertEquals(res, Left(IdentityEncError.IdentityNotFound),
      "snapshot from before bob's issuance must not contain bob")
  }

  test("DirectoryEntryWire round-trip: encode → decode recovers (identity, mailboxId, publicBundle)") {
    import siida.crypto.api.HybridOnion
    val (_, public) = HybridOnion.generateBundle(fixedRng("dew"))
    val identity = "alice@siida".getBytes("UTF-8")
    val mailboxId = 42L
    val bytes = DirectoryEntryWire.encode(identity, mailboxId, public)
    val (id2, mid2, pub2) = DirectoryEntryWire.decode(bytes).get
    assertEquals(id2.toSeq, identity.toSeq)
    assertEquals(mid2, mailboxId)
    assertEquals(
      HybridOnion.serialisePublicBundle(pub2).toSeq,
      HybridOnion.serialisePublicBundle(public).toSeq)
  }
