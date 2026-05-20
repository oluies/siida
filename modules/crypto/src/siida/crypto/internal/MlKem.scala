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
import org.bouncycastle.pqc.crypto.crystals.kyber.{
  KyberKeyGenerationParameters,
  KyberKeyPairGenerator,
  KyberParameters,
  KyberKEMGenerator,
  KyberKEMExtractor,
  KyberPublicKeyParameters,
  KyberPrivateKeyParameters,
}
import siida.crypto.api.HybridOnionError

/** Bouncy Castle ML-KEM-768 (FIPS 203, BC class names retain the
 *  legacy "Kyber" identifier — same algorithm).
 *
 *  Wire sizes (FIPS 203, parameter set 3):
 *    public key       : 1184 bytes
 *    secret key       : 2400 bytes
 *    ciphertext       : 1088 bytes
 *    shared secret    :   32 bytes
 */
object MlKem:

  inline val PublicKeyBytes      = 1184
  inline val SecretKeyBytes      = 2400
  inline val CiphertextBytes     = 1088
  inline val SharedSecretBytes   = 32

  // Kyber768 in BC's nomenclature == ML-KEM-768 per FIPS 203
  private val params = KyberParameters.kyber768

  /** Generate a fresh ML-KEM-768 keypair. Returns `(skBytes, pkBytes)`. */
  def keygen(rng: SecureRandom): (Array[Byte], Array[Byte]) =
    val gen = KyberKeyPairGenerator()
    gen.init(KyberKeyGenerationParameters(rng, params))
    val pair = gen.generateKeyPair()
    val sk = pair.getPrivate.asInstanceOf[KyberPrivateKeyParameters].getEncoded
    val pk = pair.getPublic.asInstanceOf[KyberPublicKeyParameters].getEncoded
    (sk, pk)

  /** Encapsulate a shared secret to a recipient's public key. Returns
   *  `(ciphertext, sharedSecret)`.
   */
  def encap(pkBytes: Array[Byte], rng: SecureRandom): (Array[Byte], Array[Byte]) =
    val pk = KyberPublicKeyParameters(params, pkBytes)
    val enc = KyberKEMGenerator(rng)
    val sec = enc.generateEncapsulated(pk)
    (sec.getEncapsulation, sec.getSecret)

  /** Decapsulate a ciphertext using the recipient's secret key.
   *  Returns `Left(DecapsulationFailed)` on any error — including
   *  BC's internal exceptions for malformed input.
   */
  def decap(skBytes: Array[Byte], ct: Array[Byte]): Either[HybridOnionError, Array[Byte]] =
    if skBytes.length != SecretKeyBytes || ct.length != CiphertextBytes then
      Left(HybridOnionError.InvalidLength)
    else
      try
        val sk = KyberPrivateKeyParameters(params, skBytes)
        val ext = KyberKEMExtractor(sk)
        Right(ext.extractSecret(ct))
      catch
        case _: Throwable => Left(HybridOnionError.DecapsulationFailed)
