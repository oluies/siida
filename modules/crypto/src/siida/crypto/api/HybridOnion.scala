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
import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}
import siida.crypto.internal.{Combiner, HybridOnionWire, MlKem, X25519}

/** Post-quantum hybrid mixnet onion layer per spec 012:
 *
 *    classical : x25519 ephemeral ECDH
 *    PQ        : ML-KEM-768 (FIPS 203)
 *    combiner  : SHA3-256(classical_ss || ml_kem_ss || DST)
 *    AEAD      : ChaCha20-Poly1305 (RFC 8439)
 *
 *  The combined-secret derivation gives `max(classical, PQ)` security
 *  — an adversary who breaks only one of the two halves cannot
 *  distinguish the AEAD key from random.
 *
 *  Wire format (per contracts/wire-format.md):
 *    1-byte algorithm ID (0x01) + 32-byte x25519 ephemeral pk +
 *    1088-byte ML-KEM ciphertext + AEAD ciphertext+tag.
 *
 *  Single-layer use: the nonce is fixed (all-zero) because each
 *  call generates a fresh ephemeral key, so the AEAD key is unique
 *  per call. Multi-hop composition (spec 004 / 007) MUST derive
 *  per-layer nonces from layer position when reusing the same
 *  underlying AEAD key — but this primitive doesn't reuse keys.
 */
object HybridOnion:

  // ── Opaque type API ─────────────────────────────────────────────

  opaque type HybridPublicBundle = HybridPublicBundleRepr
  opaque type HybridSecretBundle = HybridSecretBundleRepr
  opaque type OnionLayer         = OnionLayerRepr

  private final case class HybridPublicBundleRepr(
    x25519Pk: Array[Byte],
    mlKemPk:  Array[Byte],
  )
  private final case class HybridSecretBundleRepr(
    x25519Sk: Array[Byte],
    mlKemSk:  Array[Byte],
  )
  private final case class OnionLayerRepr(bytes: Array[Byte])

  // ── Constants ──────────────────────────────────────────────────

  object AlgorithmID:
    val DeprecatedClassical: Byte    = HybridOnionWire.AlgDeprecatedClassical
    val Hybrid_MlKem768_x25519_v1: Byte = HybridOnionWire.AlgHybridV1

  /** AEAD nonce for single-layer use. Fresh ephemeral key per call
   *  → nonce reuse is impossible across different calls; an all-zero
   *  nonce is safe. Multi-hop composition (spec 004) overrides this
   *  with position-derived nonces.
   */
  private val SingleLayerNonce: Array[Byte] = new Array[Byte](12)

  // Public bundle / secret bundle sizes (per contracts/wire-format.md)
  private inline val PublicBundleBytes = 1216 // 32 + 1184
  private inline val SecretBundleBytes = 2432 // 32 + 2400

  // ── Keypair generation ─────────────────────────────────────────

  def generateBundle(rng: SecureRandom): (HybridSecretBundle, HybridPublicBundle) =
    val (xSk, xPk) = X25519.keygen(rng)
    val (kSk, kPk) = MlKem.keygen(rng)
    val secret = HybridSecretBundleRepr(xSk, kSk)
    val public = HybridPublicBundleRepr(xPk, kPk)
    (secret, public)

  def publicBundle(secret: HybridSecretBundle): HybridPublicBundle =
    val xPk = X25519.publicKey(secret.x25519Sk)
      .getOrElse(throw new RuntimeException("HybridOnion.publicBundle: secret.x25519Sk rejected; bundle corrupted"))
    // The ML-KEM public key is derivable from the secret but BC
    // doesn't expose a public-key-from-secret-key API directly.
    // Recover by re-parsing the secret-key bytes — BC's
    // KyberPrivateKeyParameters carries the embedded public key.
    val kPk = mlKemPkFromSk(secret.mlKemSk)
    HybridPublicBundleRepr(xPk, kPk)

  // ── Encrypt / Decrypt ──────────────────────────────────────────

  def encrypt(
    recipient: HybridPublicBundle,
    payload:   Array[Byte],
    rng:       SecureRandom,
  ): OnionLayer =
    // FR-005: refuse on an incomplete bundle. The bundle is opaque
    // so an "incomplete" form can only arise from a buggy caller
    // constructing it through an unsupported path. We sanity-check
    // sizes; if either is wrong, throw (it's a programming bug, not
    // a per-call cryptographic failure).
    require(recipient.x25519Pk.length == X25519.PointBytes,
      "HybridOnion.encrypt: recipient x25519_pk wrong length")
    require(recipient.mlKemPk.length == MlKem.PublicKeyBytes,
      "HybridOnion.encrypt: recipient ml_kem_pk wrong length")

    // 1. Generate the per-layer x25519 ephemeral keypair
    val (ephSk, ephPk) = X25519.keygen(rng)

    // 2. Classical ECDH against the recipient's x25519 pk
    val classicalSs = X25519.ecdh(ephSk, recipient.x25519Pk)
      .getOrElse(throw new RuntimeException("HybridOnion.encrypt: ephemeral ECDH failed"))

    // 3. ML-KEM encapsulation to the recipient's ml_kem pk
    val (mlKemCt, mlKemSs) = MlKem.encap(recipient.mlKemPk, rng)

    // 4. Combine into the AEAD key
    val aeadKey = Combiner.combine(classicalSs, mlKemSs, Combiner.OnionLayerDST)

    // 5. ChaCha20-Poly1305 encrypt
    val aeadCtTag = aeadEncrypt(aeadKey, SingleLayerNonce, payload)

    // 6. Pack the wire envelope
    val wire = HybridOnionWire.pack(
      HybridOnionWire.AlgHybridV1,
      ephPk,
      mlKemCt,
      aeadCtTag,
    )
    OnionLayerRepr(wire)

  def decrypt(
    secret: HybridSecretBundle,
    layer:  OnionLayer,
  ): Either[HybridOnionError, Array[Byte]] =
    HybridOnionWire.unpack(layer.bytes).flatMap { case (_, ephPk, mlKemCt, aeadCtTag) =>
      // FR-006: uniform error on any failure — we collapse to
      // DecapsulationFailed for everything past the wire-format
      // checks. No side channel on which side broke.
      val attempt =
        for
          classicalSs <- X25519.ecdh(secret.x25519Sk, ephPk)
                           .left.map(_ => HybridOnionError.DecapsulationFailed)
          mlKemSs     <- MlKem.decap(secret.mlKemSk, mlKemCt)
                           .left.map(_ => HybridOnionError.DecapsulationFailed)
          aeadKey      = Combiner.combine(classicalSs, mlKemSs, Combiner.OnionLayerDST)
          plain       <- aeadDecrypt(aeadKey, SingleLayerNonce, aeadCtTag)
        yield plain
      attempt
    }

  // ── Serialisation ──────────────────────────────────────────────

  def serialiseLayer(layer: OnionLayer): Array[Byte] = layer.bytes.clone()

  def deserialiseLayer(bytes: Array[Byte]): Either[HybridOnionError, OnionLayer] =
    HybridOnionWire.unpack(bytes).map(_ => OnionLayerRepr(bytes.clone()))

  def serialisePublicBundle(b: HybridPublicBundle): Array[Byte] =
    val out = new Array[Byte](PublicBundleBytes)
    System.arraycopy(b.x25519Pk, 0, out, 0, X25519.PointBytes)
    System.arraycopy(b.mlKemPk, 0, out, X25519.PointBytes, MlKem.PublicKeyBytes)
    out

  def deserialisePublicBundle(bytes: Array[Byte]): Either[HybridOnionError, HybridPublicBundle] =
    if bytes.length != PublicBundleBytes then Left(HybridOnionError.InvalidLength)
    else
      val xPk = java.util.Arrays.copyOfRange(bytes, 0, X25519.PointBytes)
      val kPk = java.util.Arrays.copyOfRange(bytes, X25519.PointBytes, PublicBundleBytes)
      Right(HybridPublicBundleRepr(xPk, kPk))

  def serialiseSecretBundle(b: HybridSecretBundle): Array[Byte] =
    val out = new Array[Byte](SecretBundleBytes)
    System.arraycopy(b.x25519Sk, 0, out, 0, X25519.ScalarBytes)
    System.arraycopy(b.mlKemSk, 0, out, X25519.ScalarBytes, MlKem.SecretKeyBytes)
    out

  def deserialiseSecretBundle(bytes: Array[Byte]): Either[HybridOnionError, HybridSecretBundle] =
    if bytes.length != SecretBundleBytes then Left(HybridOnionError.InvalidLength)
    else
      val xSk = java.util.Arrays.copyOfRange(bytes, 0, X25519.ScalarBytes)
      val kSk = java.util.Arrays.copyOfRange(bytes, X25519.ScalarBytes, SecretBundleBytes)
      Right(HybridSecretBundleRepr(xSk, kSk))

  // ── Internal AEAD helpers ──────────────────────────────────────

  private def aeadEncrypt(
    key:       Array[Byte],
    nonce:     Array[Byte],
    plaintext: Array[Byte],
  ): Array[Byte] =
    val cipher = Cipher.getInstance("ChaCha20-Poly1305")
    cipher.init(
      Cipher.ENCRYPT_MODE,
      SecretKeySpec(key, "ChaCha20"),
      IvParameterSpec(nonce),
    )
    cipher.doFinal(plaintext)

  private def aeadDecrypt(
    key:        Array[Byte],
    nonce:      Array[Byte],
    ciphertext: Array[Byte],
  ): Either[HybridOnionError, Array[Byte]] =
    try
      val cipher = Cipher.getInstance("ChaCha20-Poly1305")
      cipher.init(
        Cipher.DECRYPT_MODE,
        SecretKeySpec(key, "ChaCha20"),
        IvParameterSpec(nonce),
      )
      Right(cipher.doFinal(ciphertext))
    catch
      case _: Throwable => Left(HybridOnionError.DecapsulationFailed)

  // ── ML-KEM public-key recovery from secret ─────────────────────

  /** BC's MLKEMPrivateKeyParameters embeds the public key. We re-
   *  construct the parameters from the serialised secret bytes and
   *  read back the public-key half.
   */
  private def mlKemPkFromSk(skBytes: Array[Byte]): Array[Byte] =
    import org.bouncycastle.crypto.params.{
      MLKEMParameters,
      MLKEMPrivateKeyParameters,
    }
    val sk = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, skBytes)
    // BC's encoded secret key concatenates several pieces; the
    // recoverable public-key bytes live at a known offset. The
    // MLKEMPrivateKeyParameters object exposes a getPublicKey()
    // method that returns the parameters; we ask for its encoded
    // form.
    val pk = sk.getPublicKeyParameters
    pk.getEncoded
