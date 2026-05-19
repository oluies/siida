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

/** Thin Scala-level wrappers around the native BN254 primitives.
 *  Allocates the right-sized output buffer, calls the native function,
 *  and translates the return code to Either via BytesOps.
 *
 *  This is the layer the public API objects (IBE, BLS, BN254) call;
 *  it stays inside `internal` so the public API can stay narrower.
 */
object Bn254Ops:

  // ── Generators ───────────────────────────────────────────────────

  def g1Generator(): Array[Byte] =
    val out = BytesOps.newG1Buf
    Native.lib.siida_bn254_g1_generator(out)
    out

  def g2Generator(): Array[Byte] =
    val out = BytesOps.newG2Buf
    Native.lib.siida_bn254_g2_generator(out)
    out

  // ── Scalar mul ───────────────────────────────────────────────────

  def g1ScalarMul(scalar: Array[Byte], point: Array[Byte]): Either[BN254Error, Array[Byte]] =
    for
      _ <- BytesOps.checkLength(scalar, Native.SCALAR_BYTES)
      _ <- BytesOps.checkLength(point, Native.G1_BYTES)
      out = BytesOps.newG1Buf
      _ <- BytesOps.returnCodeToEither(
        Native.lib.siida_bn254_g1_scalar_mul(scalar, point, out)
      )
    yield out

  def g2ScalarMul(scalar: Array[Byte], point: Array[Byte]): Either[BN254Error, Array[Byte]] =
    for
      _ <- BytesOps.checkLength(scalar, Native.SCALAR_BYTES)
      _ <- BytesOps.checkLength(point, Native.G2_BYTES)
      out = BytesOps.newG2Buf
      _ <- BytesOps.returnCodeToEither(
        Native.lib.siida_bn254_g2_scalar_mul(scalar, point, out)
      )
    yield out

  // ── Add ─────────────────────────────────────────────────────────

  def g1Add(p: Array[Byte], q: Array[Byte]): Either[BN254Error, Array[Byte]] =
    for
      _ <- BytesOps.checkLength(p, Native.G1_BYTES)
      _ <- BytesOps.checkLength(q, Native.G1_BYTES)
      out = BytesOps.newG1Buf
      _ <- BytesOps.returnCodeToEither(
        Native.lib.siida_bn254_g1_add(p, q, out)
      )
    yield out

  def g2Add(p: Array[Byte], q: Array[Byte]): Either[BN254Error, Array[Byte]] =
    for
      _ <- BytesOps.checkLength(p, Native.G2_BYTES)
      _ <- BytesOps.checkLength(q, Native.G2_BYTES)
      out = BytesOps.newG2Buf
      _ <- BytesOps.returnCodeToEither(
        Native.lib.siida_bn254_g2_add(p, q, out)
      )
    yield out

  // ── Negation ────────────────────────────────────────────────────

  def g1Neg(point: Array[Byte]): Either[BN254Error, Array[Byte]] =
    for
      _ <- BytesOps.checkLength(point, Native.G1_BYTES)
      out = BytesOps.newG1Buf
      _ <- BytesOps.returnCodeToEither(Native.lib.siida_bn254_g1_neg(point, out))
    yield out

  // ── Pairings ────────────────────────────────────────────────────

  def pairing(g1: Array[Byte], g2: Array[Byte]): Either[BN254Error, Array[Byte]] =
    for
      _ <- BytesOps.checkLength(g1, Native.G1_BYTES)
      _ <- BytesOps.checkLength(g2, Native.G2_BYTES)
      out = BytesOps.newGtBuf
      _ <- BytesOps.returnCodeToEither(
        Native.lib.siida_bn254_pairing(g1, g2, out)
      )
    yield out

  /** Multi-pairing check. Pairs are zipped into packed byte buffers
   *  before crossing the FFI boundary. Empty input returns
   *  Left(InvalidLength) because an empty product is trivially 1
   *  and the caller almost certainly meant something else.
   */
  def pairingCheck(pairs: Seq[(Array[Byte], Array[Byte])]): Either[BN254Error, Boolean] =
    if pairs.isEmpty then Left(BN254Error.InvalidLength)
    else
      val n = pairs.length
      // All G1s wrong-sized or all G2s wrong-sized is the only way
      // to fail length checks; do them up front rather than per-pair.
      pairs.find { case (g1, g2) =>
        g1.length != Native.G1_BYTES || g2.length != Native.G2_BYTES
      } match
        case Some(_) => Left(BN254Error.InvalidLength)
        case None    =>
          val packedG1 = new Array[Byte](n * Native.G1_BYTES)
          val packedG2 = new Array[Byte](n * Native.G2_BYTES)
          var i = 0
          while i < n do
            val (g1, g2) = pairs(i)
            System.arraycopy(g1, 0, packedG1, i * Native.G1_BYTES, Native.G1_BYTES)
            System.arraycopy(g2, 0, packedG2, i * Native.G2_BYTES, Native.G2_BYTES)
            i += 1
          val rc = Native.lib.siida_bn254_pairing_check(packedG1, packedG2, n.toLong)
          rc match
            case 0 => Right(true)
            case 1 => Right(false)
            case _ => BytesOps.returnCodeToEither(rc).map(_ => false) // propagates the error

  // ── Hash to G2 ──────────────────────────────────────────────────

  def g2HashToCurve(message: Array[Byte], dst: Array[Byte]): Either[BN254Error, Array[Byte]] =
    val out = BytesOps.newG2Buf
    BytesOps.returnCodeToEither(
      Native.lib.siida_bn254_g2_hash_to_curve(
        message, message.length.toLong, dst, dst.length.toLong, out,
      )
    ).map(_ => out)

  // ── Subgroup checks ─────────────────────────────────────────────

  def g1SubgroupCheck(point: Array[Byte]): Either[BN254Error, Unit] =
    for
      _ <- BytesOps.checkLength(point, Native.G1_BYTES)
      _ <- BytesOps.returnCodeToEither(Native.lib.siida_bn254_g1_subgroup_check(point))
    yield ()

  def g2SubgroupCheck(point: Array[Byte]): Either[BN254Error, Unit] =
    for
      _ <- BytesOps.checkLength(point, Native.G2_BYTES)
      _ <- BytesOps.returnCodeToEither(Native.lib.siida_bn254_g2_subgroup_check(point))
    yield ()

  // ── Scalar reduce ───────────────────────────────────────────────

  def scalarReduce(in: Array[Byte]): Array[Byte] =
    val padded =
      if in.length == Native.SCALAR_BYTES then in
      else if in.length < Native.SCALAR_BYTES then
        val p = new Array[Byte](Native.SCALAR_BYTES)
        System.arraycopy(in, 0, p, Native.SCALAR_BYTES - in.length, in.length)
        p
      else
        // too long — keep the low 32 bytes
        val p = new Array[Byte](Native.SCALAR_BYTES)
        System.arraycopy(in, in.length - Native.SCALAR_BYTES, p, 0, Native.SCALAR_BYTES)
        p
    val out = BytesOps.newScalarBuf
    Native.lib.siida_bn254_scalar_reduce(padded, out)
    out
