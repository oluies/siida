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
import siida.crypto.internal.{Bn254Ops, BytesOps, HashToCurve, Native}

/** BLS signatures over the BN254 pairing (research R6).
 *  Layout: public keys in G1, signatures in G2 (matches Vuvuzela's
 *  upstream `crypto/bls`).
 *
 *    private key:  sk ∈ Z_r
 *    public key:   g1^sk ∈ G1
 *    Sign(m):      H_G2(m, BLS_DST)^sk ∈ G2
 *    Verify(pk, m, σ): e(g1, σ) == e(pk, H_G2(m))
 *    Aggregate(σ_1..σ_n): ∑ σ_i ∈ G2
 *    VerifyAggregate (same message, with PoPs):
 *                  ∀i: verifyPoP(pk_i, pop_i)
 *                  e(g1, ∑σ) == e(∑pk_i, H_G2(m))
 *    PoP(sk):      H_G2(pk_bytes, POP_DST)^sk
 *
 *  Wire format:
 *    BLSPrivateKey:      32 bytes (scalar)
 *    BLSPublicKey:       32 bytes (G1 compressed)
 *    BLSSignature:       1 byte kind tag + 64 bytes G2 = 65 bytes
 *    ProofOfPossession:  65 bytes (same shape as BLSSignature)
 */
object BLS:

  enum SignatureKind derives CanEqual:
    case Single, Aggregate

  opaque type BLSPrivateKey     = BLSPrivateKeyRepr
  opaque type BLSPublicKey      = BLSPublicKeyRepr
  opaque type BLSSignature      = BLSSignatureRepr
  opaque type ProofOfPossession = ProofOfPossessionRepr

  private final case class BLSPrivateKeyRepr(secret: Array[Byte])
  private final case class BLSPublicKeyRepr(publicG1: Array[Byte])
  private final case class BLSSignatureRepr(sigG2: Array[Byte], kind: SignatureKind)
  private final case class ProofOfPossessionRepr(popG2: Array[Byte])

  // Memoised generator — fetched once per JVM rather than on every call.
  private lazy val g1Gen: Array[Byte] = Bn254Ops.g1Generator()

  // Wire-format constants
  private final val KindSingle: Byte    = 0
  private final val KindAggregate: Byte = 1
  private inline val SignatureBytes     = 65 // 1 + Native.G2_BYTES

  // ── Keypair generation ─────────────────────────────────────────

  def generateKeyPair(rng: SecureRandom): (BLSPrivateKey, BLSPublicKey) =
    val secret = randomScalar(rng)
    val pkBytes = Bn254Ops.g1ScalarMul(secret, g1Gen)
      .getOrElse(throw RuntimeException("BLS: g1^sk failed; gnark-crypto rejected the scalar"))
    (BLSPrivateKeyRepr(secret), BLSPublicKeyRepr(pkBytes))

  def publicKey(sk: BLSPrivateKey): BLSPublicKey =
    val pkBytes = Bn254Ops.g1ScalarMul(sk.secret, g1Gen)
      .getOrElse(throw RuntimeException("BLS: publicKey g1^sk failed"))
    BLSPublicKeyRepr(pkBytes)

  // ── Sign / Verify ──────────────────────────────────────────────

  def sign(sk: BLSPrivateKey, message: Array[Byte]): BLSSignature =
    val hG2 = HashToCurve.forBLS(message)
      .getOrElse(throw RuntimeException("BLS: sign hash-to-G2 failed"))
    val sig = Bn254Ops.g2ScalarMul(sk.secret, hG2)
      .getOrElse(throw RuntimeException("BLS: sign g2^sk failed"))
    BLSSignatureRepr(sig, SignatureKind.Single)

  /** Verify a single signature. Returns false (NOT an exception) on any
   *  failure mode — invalid point, hash failure, pairing mismatch.
   *  Programming errors (wrong-length buffers crossing FFI) still throw.
   */
  def verify(pk: BLSPublicKey, message: Array[Byte], sig: BLSSignature): Boolean =
    HashToCurve.forBLS(message) match
      case Left(_) => false
      case Right(hG2) =>
        pairingEqual(g1Gen, sig.sigG2, pk.publicG1, hG2)

  // ── Aggregate ─────────────────────────────────────────────────

  def aggregate(sigs: Seq[BLSSignature]): Either[BLSError, BLSSignature] =
    if sigs.isEmpty then Left(BLSError.EmptyAggregation)
    else
      val agg = sigs.tail.foldLeft[Either[BLSError, Array[Byte]]](Right(sigs.head.sigG2)) {
        case (Left(e), _) => Left(e)
        case (Right(acc), s) =>
          Bn254Ops.g2Add(acc, s.sigG2) match
            case Right(sum) => Right(sum)
            case Left(_)    => Left(BLSError.InvalidPoint)
      }
      agg.map(bytes => BLSSignatureRepr(bytes, SignatureKind.Aggregate))

  /** Verify an aggregate signature over the SAME message by multiple
   *  signers. Every public key MUST carry a valid proof-of-possession
   *  to defend against rogue-key attacks. Returns false on any
   *  failure mode.
   */
  def verifyAggregate(
    pks:     Seq[BLSPublicKey],
    pops:    Seq[ProofOfPossession],
    message: Array[Byte],
    aggSig:  BLSSignature,
  ): Boolean =
    if pks.isEmpty || pks.length != pops.length then false
    else if !pks.lazyZip(pops).forall((pk, pop) => verifyPoP(pk, pop)) then false
    else
      HashToCurve.forBLS(message) match
        case Left(_) => false
        case Right(hG2) =>
          val sumPkE = pks.tail.foldLeft[Either[BLSError, Array[Byte]]](Right(pks.head.publicG1)) {
            case (Left(e), _) => Left(e)
            case (Right(acc), pk) =>
              Bn254Ops.g1Add(acc, pk.publicG1) match
                case Right(sum) => Right(sum)
                case Left(_)    => Left(BLSError.InvalidPoint)
          }
          sumPkE match
            case Left(_)      => false
            case Right(sumPk) =>
              pairingEqual(g1Gen, aggSig.sigG2, sumPk, hG2)

  /** Verify an aggregate signature over DISTINCT messages. Requires
   *  a multi-pairing product (∏ e(pk_i, H_G2(msg_i)) == e(g1, aggSig))
   *  which in turn needs either GT multiplication or G1 negation
   *  exposed at the native ABI. Neither is in 002's first cut.
   *
   *  Throws UnsupportedOperationException; a follow-up PR will
   *  extend `siida_bn254_*` with G1 negation and implement this via
   *  the existing pairing-check primitive.
   */
  def verifyAggregateDistinct(
    @scala.annotation.unused pkMsgPairs: Seq[(BLSPublicKey, Array[Byte])],
    @scala.annotation.unused aggSig:     BLSSignature,
  ): Boolean =
    throw UnsupportedOperationException(
      "BLS.verifyAggregateDistinct is not implemented in 002's first cut. " +
        "It requires a multi-pairing product or G1 negation that's not yet " +
        "in the native ABI. Follow-up PR will extend siida_bn254_g1_neg."
    )

  // ── Proofs of possession ──────────────────────────────────────

  def proofOfPossession(sk: BLSPrivateKey): ProofOfPossession =
    val pkBytes = Bn254Ops.g1ScalarMul(sk.secret, g1Gen)
      .getOrElse(throw RuntimeException("BLS: PoP g1^sk failed"))
    val hG2 = HashToCurve.forPoP(pkBytes)
      .getOrElse(throw RuntimeException("BLS: PoP hash-to-G2 failed"))
    val pop = Bn254Ops.g2ScalarMul(sk.secret, hG2)
      .getOrElse(throw RuntimeException("BLS: PoP g2^sk failed"))
    ProofOfPossessionRepr(pop)

  def verifyPoP(pk: BLSPublicKey, pop: ProofOfPossession): Boolean =
    HashToCurve.forPoP(pk.publicG1) match
      case Left(_) => false
      case Right(hG2) =>
        pairingEqual(g1Gen, pop.popG2, pk.publicG1, hG2)

  // ── Serialisation ─────────────────────────────────────────────

  def serialisePrivateKey(sk: BLSPrivateKey): Array[Byte] =
    sk.secret.clone()

  def deserialisePrivateKey(bytes: Array[Byte]): Either[BLSError, BLSPrivateKey] =
    if bytes.length != Native.SCALAR_BYTES then Left(BLSError.InvalidKey)
    else Right(BLSPrivateKeyRepr(bytes.clone()))

  def serialisePublicKey(pk: BLSPublicKey): Array[Byte] =
    pk.publicG1.clone()

  def deserialisePublicKey(bytes: Array[Byte]): Either[BLSError, BLSPublicKey] =
    if bytes.length != Native.G1_BYTES then Left(BLSError.InvalidPoint)
    else
      Bn254Ops.g1SubgroupCheck(bytes) match
        case Right(_) => Right(BLSPublicKeyRepr(bytes.clone()))
        case Left(_)  => Left(BLSError.InvalidPoint)

  def serialiseSignature(sig: BLSSignature): Array[Byte] =
    val out = new Array[Byte](SignatureBytes)
    out(0) = if sig.kind == SignatureKind.Single then KindSingle else KindAggregate
    System.arraycopy(sig.sigG2, 0, out, 1, Native.G2_BYTES)
    out

  def deserialiseSignature(bytes: Array[Byte]): Either[BLSError, BLSSignature] =
    if bytes.length != SignatureBytes then Left(BLSError.InvalidSignature)
    else
      val kindTag = bytes(0)
      val kind =
        if kindTag == KindSingle then SignatureKind.Single
        else if kindTag == KindAggregate then SignatureKind.Aggregate
        else return Left(BLSError.InvalidSignature)
      val sigG2 = java.util.Arrays.copyOfRange(bytes, 1, SignatureBytes)
      Bn254Ops.g2SubgroupCheck(sigG2) match
        case Right(_) => Right(BLSSignatureRepr(sigG2, kind))
        case Left(_)  => Left(BLSError.InvalidPoint)

  def serialisePoP(pop: ProofOfPossession): Array[Byte] =
    // PoP wire format matches BLSSignature (Single) — 65 bytes
    val out = new Array[Byte](SignatureBytes)
    out(0) = KindSingle
    System.arraycopy(pop.popG2, 0, out, 1, Native.G2_BYTES)
    out

  def deserialisePoP(bytes: Array[Byte]): Either[BLSError, ProofOfPossession] =
    if bytes.length != SignatureBytes then Left(BLSError.InvalidPOP)
    else if bytes(0) != KindSingle then Left(BLSError.InvalidPOP)
    else
      val popG2 = java.util.Arrays.copyOfRange(bytes, 1, SignatureBytes)
      Bn254Ops.g2SubgroupCheck(popG2) match
        case Right(_) => Right(ProofOfPossessionRepr(popG2))
        case Left(_)  => Left(BLSError.InvalidPoint)

  // ── Internal helpers ─────────────────────────────────────────

  private def randomScalar(rng: SecureRandom): Array[Byte] =
    val buf = new Array[Byte](Native.SCALAR_BYTES)
    rng.nextBytes(buf)
    Bn254Ops.scalarReduce(buf)

  /** True iff e(p1, q1) == e(p2, q2). Compared via canonical GT byte
   *  representations from gnark-crypto. Constant-time over the GT
   *  byte buffers.
   */
  private def pairingEqual(
    p1: Array[Byte], q1: Array[Byte],
    p2: Array[Byte], q2: Array[Byte],
  ): Boolean =
    (Bn254Ops.pairing(p1, q1), Bn254Ops.pairing(p2, q2)) match
      case (Right(left), Right(right)) =>
        BytesOps.constantTimeEquals(left, right)
      case _ => false
