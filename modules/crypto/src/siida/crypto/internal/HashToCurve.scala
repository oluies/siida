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

package siida.crypto.internal

import siida.crypto.api.BN254Error

/** Builds the per-usage IETF-style domain-separation tag and delegates
 *  to the native SSWU hash-to-G2 implementation.
 *
 *  The DST scheme follows research R7:
 *    suite-prefix = "SIIDA-BN254-G2-SSWU-RO-"
 *    DST          = suite-prefix + per-usage suffix
 *
 *  Per-usage suffixes:
 *    "IBE"  — Boneh-Franklin identity hash
 *    "BLS"  — BLS signature message hash
 *    "POP"  — BLS proof-of-possession hash
 *
 *  Adding a new usage means adding a new factory method here AND
 *  reviewing for DST-collision with existing usages.
 */
object HashToCurve:

  private val SuitePrefix: Array[Byte] =
    "SIIDA-BN254-G2-SSWU-RO-".getBytes("US-ASCII")

  private def dst(usageSuffix: String): Array[Byte] =
    SuitePrefix ++ usageSuffix.getBytes("US-ASCII")

  private val IbeDst: Array[Byte] = dst("IBE")
  private val BlsDst: Array[Byte] = dst("BLS")
  private val PopDst: Array[Byte] = dst("POP")

  /** Hash for Boneh-Franklin IBE identity → G2. */
  def forIBE(identity: Array[Byte]): Either[BN254Error, Array[Byte]] =
    Bn254Ops.g2HashToCurve(identity, IbeDst)

  /** Hash for BLS signature message → G2. */
  def forBLS(message: Array[Byte]): Either[BN254Error, Array[Byte]] =
    Bn254Ops.g2HashToCurve(message, BlsDst)

  /** Hash for BLS proof-of-possession over the signer's own public
   *  key → G2. Domain-separated from BLS message hashing so a PoP
   *  cannot be confused with a signature on the same byte string.
   */
  def forPoP(publicKeyBytes: Array[Byte]): Either[BN254Error, Array[Byte]] =
    Bn254Ops.g2HashToCurve(publicKeyBytes, PopDst)
