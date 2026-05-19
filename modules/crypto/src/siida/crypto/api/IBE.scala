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

import java.security.{MessageDigest, SecureRandom}
import siida.crypto.internal.{Bn254Ops, BytesOps, HashToCurve, Kdf, Native}

/** Boneh-Franklin Identity-Based Encryption over the BN254 pairing.
 *  Construction (research R5):
 *    - master secret key:    s ∈ Z_r  (random scalar)
 *    - master public key:    g1^s ∈ G1
 *    - per-identity key:     H_G2(identity)^s ∈ G2
 *    - encrypt(M, id, r):    c1 = g1^r,
 *                            c2 = M XOR HKDF(e(MPK, H_G2(id))^r)
 *    - decrypt(ct, idk):     M = c2 XOR HKDF(e(c1, idk))
 *
 *  Bilinearity gives:
 *    e(c1, idk) = e(g1^r, H_G2(id)^s) = e(g1, H_G2(id))^(r*s)
 *    e(MPK, H_G2(id))^r = e(g1^s, H_G2(id))^r = e(g1, H_G2(id))^(s*r)
 *  → same GT element → KDF outputs match → XOR recovers M.
 *
 *  Wire format:
 *    MasterPublicKey:    32 bytes  (G1 compressed)
 *    IdentityKey:        64 bytes G2  ++  identity bytes (positional)
 *    Ciphertext:         32 bytes c1 ++ 16 bytes identityTag ++ c2 bytes
 *
 *  `identityTag` is the first 16 bytes of SHA-256(identity). It is a
 *  PUBLIC hint that lets decrypt refuse a wrong-identity attempt
 *  cheaply; it is NOT the cryptographic protection (the IBE
 *  construction itself protects).
 */
object IBE:

  // ── Opaque type API ─────────────────────────────────────────────
  // Each public opaque type aliases a private case class with the
  // actual field representation; opaque types are transparent within
  // this object, opaque to callers.

  opaque type MasterKey       = MasterKeyRepr
  opaque type MasterPublicKey = MasterPublicKeyRepr
  opaque type IdentityKey     = IdentityKeyRepr
  opaque type Ciphertext      = CiphertextRepr

  private final case class MasterKeyRepr(secret: Array[Byte], publicG1: Array[Byte])
  private final case class MasterPublicKeyRepr(publicG1: Array[Byte])
  private final case class IdentityKeyRepr(identity: Array[Byte], keyG2: Array[Byte])
  private final case class CiphertextRepr(c1: Array[Byte], identityTag: Array[Byte], c2: Array[Byte])

  private inline val IdentityTagBytes = 16

  // ── Key management ──────────────────────────────────────────────

  /** Generate a fresh master key pair from the supplied SecureRandom.
   *  The RNG MUST be cryptographically strong in production; tests use
   *  a deterministic stream so that KAT vectors are reproducible.
   */
  def generateMasterKey(rng: SecureRandom): MasterKey =
    val secret = randomScalar(rng)
    val publicG1 = Bn254Ops.g1ScalarMul(secret, Bn254Ops.g1Generator())
      .getOrElse(throw new RuntimeException("IBE: g1^secret failed; gnark-crypto rejected the scalar"))
    MasterKeyRepr(secret, publicG1)

  /** Publishable half of the master key. */
  def publicKey(mk: MasterKey): MasterPublicKey =
    MasterPublicKeyRepr(mk.publicG1)

  /** PKG-side: derive a per-identity decryption key. */
  def issueKey(mk: MasterKey, identity: Array[Byte]): IdentityKey =
    val hG2 = HashToCurve.forIBE(identity)
      .getOrElse(throw new RuntimeException("IBE: hash-to-G2 failed for identity"))
    val key = Bn254Ops.g2ScalarMul(mk.secret, hG2)
      .getOrElse(throw new RuntimeException("IBE: issueKey g2^secret failed"))
    IdentityKeyRepr(identity.clone(), key)

  // ── Encryption / Decryption ─────────────────────────────────────

  def encrypt(
    mpk:      MasterPublicKey,
    identity: Array[Byte],
    message:  Array[Byte],
    rng:      SecureRandom,
  ): Ciphertext =
    val r = randomScalar(rng)
    val c1 = Bn254Ops.g1ScalarMul(r, Bn254Ops.g1Generator())
      .getOrElse(throw new RuntimeException("IBE: encrypt c1 = g1^r failed"))

    val hG2 = HashToCurve.forIBE(identity)
      .getOrElse(throw new RuntimeException("IBE: encrypt hash-to-G2 failed"))

    // e(MPK, H_G2(id))^r computed as e(MPK^r, H_G2(id)) to avoid
    // exponentiating in GT.
    val mpkR = Bn254Ops.g1ScalarMul(r, mpk.publicG1)
      .getOrElse(throw new RuntimeException("IBE: encrypt MPK^r failed"))
    val gtBytes = Bn254Ops.pairing(mpkR, hG2)
      .getOrElse(throw new RuntimeException("IBE: encrypt pairing failed"))

    val keystream = Kdf.ibeKdf(gtBytes, message.length)
    val c2 = xor(message, keystream)
    val identityTag = sha256Prefix(identity, IdentityTagBytes)

    CiphertextRepr(c1, identityTag, c2)

  def decrypt(idk: IdentityKey, ct: Ciphertext): Either[IBEError, Array[Byte]] =
    val expectedTag = sha256Prefix(idk.identity, IdentityTagBytes)
    if !BytesOps.constantTimeEquals(ct.identityTag, expectedTag) then
      Left(IBEError.WrongIdentity)
    else
      Bn254Ops.pairing(ct.c1, idk.keyG2) match
        case Left(_)        => Left(IBEError.DecryptionFailed)
        case Right(gtBytes) =>
          val keystream = Kdf.ibeKdf(gtBytes, ct.c2.length)
          Right(xor(ct.c2, keystream))

  // ── Serialisation ───────────────────────────────────────────────

  def serialiseMasterPublicKey(mpk: MasterPublicKey): Array[Byte] =
    mpk.publicG1.clone()

  def deserialiseMasterPublicKey(bytes: Array[Byte]): Either[IBEError, MasterPublicKey] =
    if bytes.length != Native.G1_BYTES then
      Left(IBEError.MalformedCiphertext("MPK wrong length"))
    else
      Bn254Ops.g1SubgroupCheck(bytes) match
        case Right(_) => Right(MasterPublicKeyRepr(bytes.clone()))
        case Left(_)  => Left(IBEError.InvalidPoint)

  def serialiseIdentityKey(idk: IdentityKey): Array[Byte] =
    val out = new Array[Byte](Native.G2_BYTES + idk.identity.length)
    System.arraycopy(idk.keyG2, 0, out, 0, Native.G2_BYTES)
    System.arraycopy(idk.identity, 0, out, Native.G2_BYTES, idk.identity.length)
    out

  def deserialiseIdentityKey(bytes: Array[Byte]): Either[IBEError, IdentityKey] =
    if bytes.length < Native.G2_BYTES then Left(IBEError.InvalidKey)
    else
      val keyG2 = java.util.Arrays.copyOfRange(bytes, 0, Native.G2_BYTES)
      val identity = java.util.Arrays.copyOfRange(bytes, Native.G2_BYTES, bytes.length)
      Bn254Ops.g2SubgroupCheck(keyG2) match
        case Right(_) => Right(IdentityKeyRepr(identity, keyG2))
        case Left(_)  => Left(IBEError.InvalidPoint)

  def serialiseCiphertext(ct: Ciphertext): Array[Byte] =
    val out = new Array[Byte](Native.G1_BYTES + IdentityTagBytes + ct.c2.length)
    System.arraycopy(ct.c1, 0, out, 0, Native.G1_BYTES)
    System.arraycopy(ct.identityTag, 0, out, Native.G1_BYTES, IdentityTagBytes)
    System.arraycopy(ct.c2, 0, out, Native.G1_BYTES + IdentityTagBytes, ct.c2.length)
    out

  def deserialiseCiphertext(bytes: Array[Byte]): Either[IBEError, Ciphertext] =
    if bytes.length < Native.G1_BYTES + IdentityTagBytes then
      Left(IBEError.MalformedCiphertext(s"ciphertext too short: ${bytes.length}"))
    else
      val c1 = java.util.Arrays.copyOfRange(bytes, 0, Native.G1_BYTES)
      val identityTag = java.util.Arrays.copyOfRange(bytes, Native.G1_BYTES, Native.G1_BYTES + IdentityTagBytes)
      val c2 = java.util.Arrays.copyOfRange(bytes, Native.G1_BYTES + IdentityTagBytes, bytes.length)
      Bn254Ops.g1SubgroupCheck(c1) match
        case Right(_) => Right(CiphertextRepr(c1, identityTag, c2))
        case Left(_)  => Left(IBEError.InvalidPoint)

  // ── Internal helpers ────────────────────────────────────────────

  /** Sample a scalar by reading 32 bytes from the RNG and reducing
   *  mod r via the native helper. Returns a 32-byte big-endian
   *  scalar guaranteed to be in [0, r-1].
   */
  private def randomScalar(rng: SecureRandom): Array[Byte] =
    val buf = new Array[Byte](Native.SCALAR_BYTES)
    rng.nextBytes(buf)
    Bn254Ops.scalarReduce(buf)

  private def sha256Prefix(input: Array[Byte], n: Int): Array[Byte] =
    val md = MessageDigest.getInstance("SHA-256")
    val digest = md.digest(input)
    java.util.Arrays.copyOfRange(digest, 0, n)

  private def xor(a: Array[Byte], b: Array[Byte]): Array[Byte] =
    require(a.length == b.length, s"xor: length mismatch ${a.length} vs ${b.length}")
    val out = new Array[Byte](a.length)
    var i = 0
    while i < a.length do
      out(i) = (a(i) ^ b(i)).toByte
      i += 1
    out
