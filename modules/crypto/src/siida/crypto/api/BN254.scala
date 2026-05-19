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

package siida.crypto.api

import java.security.SecureRandom
import siida.crypto.internal.{Bn254Ops, Native}

/** Public BN254 primitives (US3, FR-010 stability gate).
 *
 *  Wraps the internal `Bn254Ops` symbols as the contract surface
 *  downstream specs (configchain 006, agent 008, observability 011)
 *  can build on. Inputs are validated at construction
 *  (subgroup-checked on `deserialise`), so the operating methods
 *  return raw values rather than `Either`. Programming errors —
 *  passing a 31-byte buffer where 32 is required, or a value that
 *  fails subgroup check despite being typed as G1Point — throw
 *  rather than carrying a Left through every signature.
 */
object BN254:

  opaque type Scalar    = Array[Byte] // 32 bytes, big-endian, reduced mod r
  opaque type G1Point   = Array[Byte] // 32 bytes (compressed)
  opaque type G2Point   = Array[Byte] // 64 bytes (compressed)
  opaque type GTElement = Array[Byte] // 384 bytes

  // ── Generators ────────────────────────────────────────────────

  lazy val G1Generator: G1Point = Bn254Ops.g1Generator()
  lazy val G2Generator: G2Point = Bn254Ops.g2Generator()

  // ── Scalars ──────────────────────────────────────────────────

  /** Reduce arbitrary 32-byte input mod r into a canonical Scalar. */
  def scalarFromBytes(bytes: Array[Byte]): Scalar =
    require(bytes.length == Native.SCALAR_BYTES,
      s"scalarFromBytes: expected ${Native.SCALAR_BYTES} bytes, got ${bytes.length}")
    Bn254Ops.scalarReduce(bytes)

  def scalarToBytes(s: Scalar): Array[Byte] = s.clone()

  def scalarRandom(rng: SecureRandom): Scalar =
    val buf = new Array[Byte](Native.SCALAR_BYTES)
    rng.nextBytes(buf)
    Bn254Ops.scalarReduce(buf)

  // ── Group operations ─────────────────────────────────────────

  def g1ScalarMul(s: Scalar, p: G1Point): G1Point =
    Bn254Ops.g1ScalarMul(s, p)
      .getOrElse(throw RuntimeException("BN254.g1ScalarMul: native call rejected validated inputs"))

  def g2ScalarMul(s: Scalar, p: G2Point): G2Point =
    Bn254Ops.g2ScalarMul(s, p)
      .getOrElse(throw RuntimeException("BN254.g2ScalarMul: native call rejected validated inputs"))

  def g1Add(a: G1Point, b: G1Point): G1Point =
    Bn254Ops.g1Add(a, b)
      .getOrElse(throw RuntimeException("BN254.g1Add: native call rejected validated inputs"))

  def g2Add(a: G2Point, b: G2Point): G2Point =
    Bn254Ops.g2Add(a, b)
      .getOrElse(throw RuntimeException("BN254.g2Add: native call rejected validated inputs"))

  /** Negate a G1 point: returns `-p` such that `p + (-p) == identity`.
   *  Used by `pairingCheck` rearrangements in BLS distinct-message
   *  aggregate verification.
   */
  def g1Neg(p: G1Point): G1Point =
    Bn254Ops.g1Neg(p)
      .getOrElse(throw RuntimeException("BN254.g1Neg: native call rejected validated input"))

  // ── Pairings ────────────────────────────────────────────────

  def pairing(p: G1Point, q: G2Point): GTElement =
    Bn254Ops.pairing(p, q)
      .getOrElse(throw RuntimeException("BN254.pairing: native call rejected validated inputs"))

  /** Multi-pairing check. True iff ∏ e(p_i, q_i) == 1. Empty input
   *  returns false (the empty product is 1, but the caller almost
   *  certainly meant something else).
   */
  def pairingCheck(pairs: Seq[(G1Point, G2Point)]): Boolean =
    if pairs.isEmpty then false
    else
      Bn254Ops.pairingCheck(pairs.map((g1, g2) => (g1, g2))) match
        case Right(b) => b
        case Left(_)  => false

  // ── Hash-to-curve ──────────────────────────────────────────

  /** Hash arbitrary bytes to G2 using the SSWU map. The
   *  `domainSeparationTag` MUST be unique to the calling protocol
   *  to prevent cross-usage signature confusion. New callers SHOULD
   *  use the per-usage helpers in `siida.crypto.internal.HashToCurve`
   *  rather than constructing DSTs by hand.
   */
  def hashToG2(message: Array[Byte], domainSeparationTag: Array[Byte]): G2Point =
    Bn254Ops.g2HashToCurve(message, domainSeparationTag)
      .getOrElse(throw RuntimeException("BN254.hashToG2: native hash-to-curve failed"))

  // ── Serialisation ──────────────────────────────────────────

  def serialiseG1(p: G1Point): Array[Byte] = p.clone()

  def deserialiseG1(bytes: Array[Byte]): Either[BN254Error, G1Point] =
    if bytes.length != Native.G1_BYTES then Left(BN254Error.InvalidLength)
    else
      Bn254Ops.g1SubgroupCheck(bytes) match
        case Right(_) => Right(bytes.clone())
        case Left(e)  => Left(e)

  def serialiseG2(p: G2Point): Array[Byte] = p.clone()

  def deserialiseG2(bytes: Array[Byte]): Either[BN254Error, G2Point] =
    if bytes.length != Native.G2_BYTES then Left(BN254Error.InvalidLength)
    else
      Bn254Ops.g2SubgroupCheck(bytes) match
        case Right(_) => Right(bytes.clone())
        case Left(e)  => Left(e)
