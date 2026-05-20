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
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.params.{
  MLDSAKeyGenerationParameters,
  MLDSAParameters,
  MLDSAPrivateKeyParameters,
  MLDSAPublicKeyParameters,
}
import org.bouncycastle.crypto.signers.MLDSASigner

/** Thin Bouncy Castle wrapper for ML-DSA-65 (FIPS 204, parameter
 *  set 3 — formerly Dilithium-65). Surfaces the four primitive
 *  operations the public `siida.crypto.api.PqSignature` API needs.
 *
 *  Wire sizes (FIPS 204, parameter set 3):
 *    public key   : 1952 bytes
 *    secret key   : 4032 bytes (BC's `getEncoded` default form,
 *                   matches NIST ACVP expected dk)
 *    signature    : 3293 bytes
 *
 *  Signing is deterministic (FIPS 204's `rnd = 0^32` path). This
 *  is a valid FIPS 204 choice and gives us reproducible signatures
 *  under fixed-seed test RNGs without any extra plumbing. Production
 *  callers get the same property — same (sk, M) → same signature —
 *  which is fine for Siida's use cases (mixer attestations, config
 *  chain entries) and matches the EUF-CMA security target.
 */
object MlDsa:

  inline val PublicKeyBytes  = 1952
  inline val SecretKeyBytes  = 4032
  inline val SignatureBytes  = 3309 // FIPS 204 Table 1, ML-DSA-65

  private val params = MLDSAParameters.ml_dsa_65

  /** Generate a fresh ML-DSA-65 keypair. Returns `(skBytes, pkBytes)`. */
  def keygen(rng: SecureRandom): (Array[Byte], Array[Byte]) =
    val gen = MLDSAKeyPairGenerator()
    gen.init(MLDSAKeyGenerationParameters(rng, params))
    val pair = gen.generateKeyPair()
    val sk = pair.getPrivate.asInstanceOf[MLDSAPrivateKeyParameters].getEncoded
    val pk = pair.getPublic.asInstanceOf[MLDSAPublicKeyParameters].getEncoded
    (sk, pk)

  /** Sign a message with ML-DSA-65 (deterministic mode, ctx = empty).
   *  Returns the 3293-byte signature. Throws on programming errors
   *  (wrong-length sk).
   */
  def sign(skBytes: Array[Byte], message: Array[Byte]): Array[Byte] =
    require(skBytes.length == SecretKeyBytes,
      s"MlDsa.sign: sk must be $SecretKeyBytes bytes, got ${skBytes.length}")
    val priv = MLDSAPrivateKeyParameters(params, skBytes)
    val signer = MLDSASigner()
    signer.init(true, priv)
    signer.update(message, 0, message.length)
    signer.generateSignature()

  /** Verify an ML-DSA-65 signature. Returns false on any verification
   *  failure (wrong key, tampered message, malformed). Throws only
   *  on programming errors (wrong-length pk or signature).
   */
  def verify(pkBytes: Array[Byte], message: Array[Byte], sigBytes: Array[Byte]): Boolean =
    if pkBytes.length != PublicKeyBytes then return false
    if sigBytes.length != SignatureBytes then return false
    try
      val pub    = MLDSAPublicKeyParameters(params, pkBytes)
      val signer = MLDSASigner()
      signer.init(false, pub)
      signer.update(message, 0, message.length)
      signer.verifySignature(sigBytes)
    catch
      case _: Throwable => false
