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

import java.security.SecureRandom
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.{
  X25519PrivateKeyParameters,
  X25519PublicKeyParameters,
}
import siida.crypto.api.HybridOnionError

/** Bouncy Castle x25519 ECDH wrapper. Used as the classical half of
 *  the 012 hybrid handshake. Pure-Java; same dependency the rest of
 *  the spec uses.
 */
object X25519:

  inline val ScalarBytes = 32
  inline val PointBytes  = 32

  /** Generate a fresh x25519 keypair. Returns `(skBytes, pkBytes)`. */
  def keygen(rng: SecureRandom): (Array[Byte], Array[Byte]) =
    val sk = X25519PrivateKeyParameters(rng)
    val pk = sk.generatePublicKey()
    (sk.getEncoded, pk.getEncoded)

  /** Derive the public key for a given x25519 secret. */
  def publicKey(skBytes: Array[Byte]): Either[HybridOnionError, Array[Byte]] =
    if skBytes.length != ScalarBytes then Left(HybridOnionError.InvalidLength)
    else
      try
        val sk = X25519PrivateKeyParameters(skBytes, 0)
        Right(sk.generatePublicKey().getEncoded)
      catch
        case _: Throwable => Left(HybridOnionError.InvalidPoint)

  /** Compute the x25519 shared secret. Returns 32 bytes on success;
   *  Left on length/encoding errors.
   */
  def ecdh(skBytes: Array[Byte], pkBytes: Array[Byte]): Either[HybridOnionError, Array[Byte]] =
    if skBytes.length != ScalarBytes || pkBytes.length != PointBytes then
      Left(HybridOnionError.InvalidLength)
    else
      try
        val sk = X25519PrivateKeyParameters(skBytes, 0)
        val pk = X25519PublicKeyParameters(pkBytes, 0)
        val agreement = X25519Agreement()
        agreement.init(sk)
        val sharedSecret = new Array[Byte](ScalarBytes)
        agreement.calculateAgreement(pk, sharedSecret, 0)
        Right(sharedSecret)
      catch
        case _: Throwable => Left(HybridOnionError.InvalidPoint)
