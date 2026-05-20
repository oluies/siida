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
import siida.crypto.api.PqSignature
import siida.pkg.api.{Pkg, PkgError}

/** Spec 005 — configuration-validation tests. */
final class PkgErrorsSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private val dst = "siida/test/v1/pkg-005-errs".getBytes("UTF-8")

  test("empty roster → EmptyRoster") {
    val res = Pkg.create(Seq.empty, Seq.empty, 1, dst)
    assertEquals(res, Left(PkgError.EmptyRoster))
  }

  test("threshold > roster size → InvalidThreshold") {
    val pairs = (0 until 3).map(i => PqSignature.generateKeyPair(fixedRng(s"err-$i")))
    val pubs  = pairs.map(_._2)
    val privs = pairs.map(_._1)
    val res = Pkg.create(pubs, privs, 5, dst)
    assertEquals(res, Left(PkgError.InvalidThreshold(5, 3)))
  }

  test("threshold = 0 → InvalidThreshold") {
    val pairs = (0 until 3).map(i => PqSignature.generateKeyPair(fixedRng(s"err-z-$i")))
    val res = Pkg.create(pairs.map(_._2), pairs.map(_._1), 0, dst)
    assertEquals(res, Left(PkgError.InvalidThreshold(0, 3)))
  }

  test("mismatched key counts → RosterKeyMismatch") {
    val pubs = (0 until 3).map(i => PqSignature.generateKeyPair(fixedRng(s"err-pub-$i"))._2)
    val privs = (0 until 2).map(i => PqSignature.generateKeyPair(fixedRng(s"err-priv-$i"))._1)
    val res = Pkg.create(pubs, privs, 2, dst)
    assertEquals(res, Left(PkgError.RosterKeyMismatch(2, 3)))
  }
