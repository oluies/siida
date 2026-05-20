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
import siida.crypto.internal.MlDsa

/** PQ digital signatures over ML-DSA-65 (FIPS 204). Replaces the
 *  classical `siida.crypto.api.BLS` API for new code. Aggregation
 *  is **intentionally absent** — no production-grade PQ aggregate
 *  signature exists, and surfacing the gap via API absence (no
 *  `aggregate` method) makes the cost-of-migration legible at the
 *  type-system level. See spec 013-pq-bls-replacement.
 *
 *  Wire formats (each starts with a 1-byte algorithm-ID prefix):
 *
 *    PqPublicKey  : 1953 bytes (alg 0x10 + 1952-byte ML-DSA-65 pk)
 *    PqPrivateKey : 4033 bytes (alg 0x10 + 4032-byte ML-DSA-65 sk)
 *    Signature    : 3310 bytes (alg 0x10 + 3309-byte ML-DSA-65 sig
 *                   per FIPS 204 Table 1)
 *
 *  Algorithm IDs reserved in `0x10–0x1F`:
 *    0x10 — ML-DSA-65 (this spec)        CURRENT
 *    0x11 — ML-DSA-87 (high assurance)   RESERVED
 *    0x12 — SLH-DSA (archival)           RESERVED
 *    0x13 — Falcon (small sigs)          RESERVED
 *    0x14–0x1F — reserved
 *
 *  Signing is deterministic per FIPS 204's `rnd = 0^32` path. Same
 *  (sk, M) produces the same signature on every architecture and
 *  every run. This trades off the modest implementation-attack
 *  resilience of hedged signing for cross-architecture
 *  reproducibility (FR-008) and a simpler API surface.
 */
object PqSignature:

  // Opaque types live INSIDE the object so the representation case
  // classes are visible from companion-scope. Same pattern as 012's
  // HybridOnion (lesson learned: top-level opaque types in Scala 3
  // can't see their representations from sibling objects, only from
  // their companion).

  opaque type PqPrivateKey = Array[Byte]
  opaque type PqPublicKey  = Array[Byte]
  opaque type Signature    = Array[Byte]

  // ── Constants ────────────────────────────────────────────────

  object AlgorithmID:
    /** Active variant — ML-DSA-65 (FIPS 204, parameter set 3). */
    val MlDsa65: Byte = 0x10

    /** Reserved for future variants — see object-level docs. */
    val ReservedMlDsa87: Byte = 0x11
    val ReservedSlhDsa:  Byte = 0x12
    val ReservedFalcon:  Byte = 0x13

  // Wire-format sizes including the 1-byte alg-ID prefix.
  private inline val PublicKeyBytes  = 1953 // 1 + MlDsa.PublicKeyBytes
  private inline val PrivateKeyBytes = 4033 // 1 + MlDsa.SecretKeyBytes
  private inline val SignatureBytes  = 3310 // 1 + MlDsa.SignatureBytes (FIPS 204)

  // ── Keygen ──────────────────────────────────────────────────

  def generateKeyPair(rng: SecureRandom): (PqPrivateKey, PqPublicKey) =
    val (skRaw, pkRaw) = MlDsa.keygen(rng)
    (prefixAlg(skRaw), prefixAlg(pkRaw))

  /** Recover the public-key wire format from a private key (BC's
   *  ML-DSA private-key encoding embeds the public-key bytes;
   *  this is a constant-time slice).
   */
  def publicKey(sk: PqPrivateKey): PqPublicKey =
    // BC's MLDSAPrivateKeyParameters carries the public key as a
    // discoverable field; we re-derive via BC to avoid relying on
    // any particular byte offset in the dk encoding.
    import org.bouncycastle.crypto.params.{MLDSAParameters, MLDSAPrivateKeyParameters}
    val priv = MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, dropAlg(sk))
    val pkBytes = priv.getPublicKeyParameters.getEncoded
    prefixAlg(pkBytes)

  // ── Sign / verify ──────────────────────────────────────────

  def sign(sk: PqPrivateKey, message: Array[Byte]): Signature =
    val sig = MlDsa.sign(dropAlg(sk), message)
    prefixAlg(sig)

  /** Verify one signature. Returns false on any failure mode —
   *  wrong key, tampered message, malformed bytes, unsupported
   *  algorithm ID. Does NOT throw on per-call failures. Programming
   *  errors (wrong-length buffers reaching the FFI) still throw.
   */
  def verify(pk: PqPublicKey, message: Array[Byte], sig: Signature): Boolean =
    val pkBytes  = dropAlg(pk)
    val sigBytes = dropAlg(sig)
    MlDsa.verify(pkBytes, message, sigBytes)

  /** Verify many signatures. Returns true iff every tuple verifies.
   *  Empty input returns false (FR-006 — the empty product is
   *  trivially true but the caller almost certainly meant something
   *  else). No side channel reveals which tuple failed (FR-013
   *  uniform refusal).
   *
   *  Implementation note: BC 1.84's public API does not expose the
   *  lattice primitives needed for the Pino-Vidaud randomised-
   *  coefficient construction (research R3). 013 ships a sequential
   *  loop over `verify` calls — semantically correct, but no
   *  CPU-saving relative to N individual verifies. A future spec
   *  may add proper batching when BC exposes the needed primitives
   *  or via a JNI to a library that does.
   */
  def batchVerify(tuples: Seq[(PqPublicKey, Array[Byte], Signature)]): Boolean =
    if tuples.isEmpty then false
    else tuples.forall { case (pk, msg, sig) => verify(pk, msg, sig) }

  // ── Serialisation ─────────────────────────────────────────

  def serialisePrivateKey(sk: PqPrivateKey): Array[Byte] = sk.clone()

  def deserialisePrivateKey(bytes: Array[Byte]): Either[PqSignatureError, PqPrivateKey] =
    decodeWireBytes(bytes, PrivateKeyBytes).map(identity)

  def serialisePublicKey(pk: PqPublicKey): Array[Byte] = pk.clone()

  def deserialisePublicKey(bytes: Array[Byte]): Either[PqSignatureError, PqPublicKey] =
    decodeWireBytes(bytes, PublicKeyBytes).map(identity)

  def serialiseSignature(sig: Signature): Array[Byte] = sig.clone()

  def deserialiseSignature(bytes: Array[Byte]): Either[PqSignatureError, Signature] =
    decodeWireBytes(bytes, SignatureBytes).map(identity)

  // ── Internal helpers ──────────────────────────────────────

  private def prefixAlg(raw: Array[Byte]): Array[Byte] =
    val out = new Array[Byte](raw.length + 1)
    out(0) = AlgorithmID.MlDsa65
    System.arraycopy(raw, 0, out, 1, raw.length)
    out

  private def dropAlg(wire: Array[Byte]): Array[Byte] =
    java.util.Arrays.copyOfRange(wire, 1, wire.length)

  private def decodeWireBytes(bytes: Array[Byte], expectedLen: Int): Either[PqSignatureError, Array[Byte]] =
    if bytes.length != expectedLen then Left(PqSignatureError.InvalidLength)
    else if bytes(0) != AlgorithmID.MlDsa65 then
      // Uniform refusal per FR-013: same error type, same code path
      // for any non-MlDsa65 byte value. No per-ID logging.
      Left(PqSignatureError.UnsupportedAlgorithm)
    else Right(bytes.clone())
