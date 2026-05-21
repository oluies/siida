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
import siida.observability.api.Telemetry
import siida.pkg.api.Pkg

/** Spec 021 — Pkg.issueIdentity records issuance + duplicate metrics. */
final class PkgTelemetrySuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  test("SC-003: 3 distinct + 1 duplicate → issued=3, rejected_duplicate=1") {
    val pairs = (0 until 3).map(i => PqSignature.generateKeyPair(fixedRng(s"pt-$i"))).toVector
    val tel = Telemetry.inMemory()
    val pkg = Pkg.create(
      rosterPublicKeys    = pairs.map(_._2),
      rosterPrivateKeys   = pairs.map(_._1),
      threshold           = 2,
      domainSeparationTag = "siida/test/v1/pkg-telemetry".getBytes("UTF-8"),
      telemetry           = tel,
    ).toOption.get

    pkg.issueIdentity("alice".getBytes("UTF-8"), fixedRng("pt-alice")).toOption.get
    pkg.issueIdentity("bob".getBytes("UTF-8"),   fixedRng("pt-bob")).toOption.get
    pkg.issueIdentity("carol".getBytes("UTF-8"), fixedRng("pt-carol")).toOption.get
    // Duplicate
    val dup = pkg.issueIdentity("alice".getBytes("UTF-8"), fixedRng("pt-alice-dup"))
    assert(dup.isLeft, s"expected Left for duplicate, got $dup")

    val s = tel.snapshot()
    assertEquals(s.counters("pkg.identity.issued"), 3L)
    assertEquals(s.counters("pkg.identity.rejected_duplicate"), 1L)
    assertEquals(s.gauges("pkg.directory.size"), 3.0)
  }

  test("default Pkg.create (no telemetry) still works (Telemetry.noop)") {
    val pairs = (0 until 2).map(i => PqSignature.generateKeyPair(fixedRng(s"def-$i"))).toVector
    val pkg = Pkg.create(
      rosterPublicKeys    = pairs.map(_._2),
      rosterPrivateKeys   = pairs.map(_._1),
      threshold           = 1,
      domainSeparationTag = "siida/test/v1/pkg-default".getBytes("UTF-8"),
    ).toOption.get
    pkg.issueIdentity("x".getBytes("UTF-8"), fixedRng("def-x")).toOption.get
    // No assertion on telemetry — just that the API is backward-compat.
  }
