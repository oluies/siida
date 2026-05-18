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

import com.sun.jna.{Library, Native as JNANative}

/** JNA interface mirroring the C ABI documented in
 *  `specs/002-crypto-pairing/contracts/native-abi.md`.
 *
 *  Every method maps to a `siida_bn254_*` C function exported by the
 *  shim. Byte arrays are marshalled directly by JNA: the JVM passes
 *  a pointer to the array's backing memory; the C side reads/writes
 *  via `uint8_t *`. Callers MUST size buffers correctly (32 / 64 /
 *  384 bytes per the ABI); JNA does not check.
 *
 *  Return codes: 0 = ok, negative = encoding error (see siidaErr*
 *  constants below), 1 = legitimate-false (pairing check only).
 */
trait NativeBN254 extends Library:

  // Lifecycle
  def siida_bn254_init(): Int

  // Generators (output-only)
  def siida_bn254_g1_generator(out: Array[Byte]): Unit
  def siida_bn254_g2_generator(out: Array[Byte]): Unit

  // Scalar mul
  def siida_bn254_g1_scalar_mul(scalar: Array[Byte], point: Array[Byte], out: Array[Byte]): Int
  def siida_bn254_g2_scalar_mul(scalar: Array[Byte], point: Array[Byte], out: Array[Byte]): Int

  // Add
  def siida_bn254_g1_add(p: Array[Byte], q: Array[Byte], out: Array[Byte]): Int
  def siida_bn254_g2_add(p: Array[Byte], q: Array[Byte], out: Array[Byte]): Int

  // Pairings
  def siida_bn254_pairing(g1: Array[Byte], g2: Array[Byte], out: Array[Byte]): Int

  /** Multi-pairing check. g1s and g2s are tightly packed; n is the
   *  number of point-pairs. JNA marshals `size_t` as a host-sized
   *  long; on the 64-bit platforms Siida supports this is 8 bytes.
   *
   *  @return 0 if ∏ e(g1[i], g2[i]) == 1, 1 if not, negative on
   *          encoding error
   */
  def siida_bn254_pairing_check(g1s: Array[Byte], g2s: Array[Byte], n: Long): Int

  // Hash to G2 (SSWU)
  def siida_bn254_g2_hash_to_curve(
    msg:    Array[Byte],
    msgLen: Long,
    dst:    Array[Byte],
    dstLen: Long,
    out:    Array[Byte],
  ): Int

  // Subgroup checks
  def siida_bn254_g1_subgroup_check(point: Array[Byte]): Int
  def siida_bn254_g2_subgroup_check(point: Array[Byte]): Int

  // Scalar utility (reduces 32-byte input mod r)
  def siida_bn254_scalar_reduce(in: Array[Byte], out: Array[Byte]): Unit


object Native:
  /** The loaded JNA proxy. Resolves on first reference; throws
   *  `UnsupportedNativeArchException` if the per-arch binary is
   *  missing from the classpath.
   */
  lazy val lib: NativeBN254 =
    val loaded = JNANative.load(
      NativeLoader.libraryPath,
      classOf[NativeBN254],
    )
    val initRc = loaded.siida_bn254_init()
    if initRc != 0 then
      throw RuntimeException(
        s"siida_bn254_init returned $initRc; native shim initialisation failed"
      )
    loaded

  // Return-code constants — keep in lockstep with main.go.
  inline val SIIDA_OK                  =   0
  inline val SIIDA_ERR_INVALID_ENCODING = -1
  inline val SIIDA_ERR_NOT_ON_CURVE    =  -2
  inline val SIIDA_ERR_NOT_IN_SUBGROUP =  -3
  inline val SIIDA_ERR_INVALID_LENGTH  =  -4
  inline val SIIDA_ERR_INTERNAL        = -99

  // Fixed-size buffer lengths.
  inline val G1_BYTES      =  32
  inline val G2_BYTES      =  64
  inline val GT_BYTES      = 384
  inline val SCALAR_BYTES  =  32
