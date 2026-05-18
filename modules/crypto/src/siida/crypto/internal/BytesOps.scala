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

/** Helpers for the fixed-size byte buffers that cross the JNA
 *  boundary, plus return-code translation.
 */
object BytesOps:

  inline def newG1Buf: Array[Byte]      = new Array[Byte](Native.G1_BYTES)
  inline def newG2Buf: Array[Byte]      = new Array[Byte](Native.G2_BYTES)
  inline def newGtBuf: Array[Byte]      = new Array[Byte](Native.GT_BYTES)
  inline def newScalarBuf: Array[Byte]  = new Array[Byte](Native.SCALAR_BYTES)

  /** Translate a native return code to either Right(()) on success or
   *  Left(BN254Error) on a known failure. Unknown negative codes map
   *  to Internal so a missing-mapping bug is visible.
   */
  def returnCodeToEither(rc: Int): Either[BN254Error, Unit] = rc match
    case Native.SIIDA_OK                  => Right(())
    case Native.SIIDA_ERR_INVALID_ENCODING => Left(BN254Error.InvalidEncoding)
    case Native.SIIDA_ERR_NOT_ON_CURVE    => Left(BN254Error.PointNotOnCurve)
    case Native.SIIDA_ERR_NOT_IN_SUBGROUP => Left(BN254Error.PointNotInSubgroup)
    case Native.SIIDA_ERR_INVALID_LENGTH  => Left(BN254Error.InvalidLength)
    case other =>
      Left(BN254Error.Internal(s"native return code $other"))

  /** Verify a byte buffer has the expected fixed size, or return a
   *  typed length error.
   */
  def checkLength(bytes: Array[Byte], expected: Int): Either[BN254Error, Array[Byte]] =
    if bytes.length == expected then Right(bytes)
    else Left(BN254Error.InvalidLength)

  /** Constant-time comparison of two byte arrays. Length mismatch is
   *  detected non-constant-time (length is a public property of the
   *  inputs); content comparison is constant-time-best-effort.
   */
  def constantTimeEquals(a: Array[Byte], b: Array[Byte]): Boolean =
    if a.length != b.length then false
    else
      var diff = 0
      var i = 0
      while i < a.length do
        diff |= (a(i).toInt ^ b(i).toInt)
        i += 1
      diff == 0
