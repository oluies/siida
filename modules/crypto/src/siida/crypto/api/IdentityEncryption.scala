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

/** PQ identity-addressed encryption. Replaces Boneh-Franklin IBE
 *  (spec 002) with a PKG-directory + `HybridOnion` (spec 012) design
 *  — a **protocol-level redesign**, not a primitive swap. See spec
 *  015-pq-identity-encryption.
 *
 *  The Boneh-Franklin property "encrypt to identity without prior
 *  key lookup" cannot be preserved with production-grade PQ
 *  primitives. Instead, senders consult a PKG-maintained directory
 *  mapping `identity → HybridPublicBundle` before encrypting.
 *  Directory entries carry a `MultiSignedEntry` proof (spec 014)
 *  attesting that the PKG roster signed off on the binding; the
 *  encrypter verifies the proof on every lookup. The crypto bulk
 *  reuses `HybridOnion.encrypt` from 012.
 *
 *  Privacy regression vs Boneh-Franklin IBE: the PKG learns "X
 *  queried for Y's bundle." Mitigated by anonymous-routing the
 *  directory queries through the mixnet (spec 007 SDK + spec 005
 *  PKG concern). See `contracts/threat-model.md`.
 *
 *  Wire format:
 *    IdentityCiphertext = 0x20-prefix-byte + HybridOnion.OnionLayer
 */
object IdentityEncryption:

  opaque type IdentityCiphertext = Array[Byte]

  object AlgorithmID:
    /** Active variant — this spec. */
    val IdentityEncryption_v1: Byte = 0x20.toByte

  // ── Encrypt / Decrypt ──────────────────────────────────────────

  /** Look up `identity` in the directory, verify its
   *  `MultiSignedEntry`, then HybridOnion-encrypt the message to
   *  the recipient's bundle.
   */
  def encrypt(
    directory: Directory,
    identity:  Array[Byte],
    message:   Array[Byte],
    rng:       SecureRandom,
  ): Either[IdentityEncError, IdentityCiphertext] =
    directory.lookup(identity).map: bundle =>
      val layer     = HybridOnion.encrypt(bundle, message, rng)
      val layerBytes = HybridOnion.serialiseLayer(layer)
      val out        = new Array[Byte](1 + layerBytes.length)
      out(0) = AlgorithmID.IdentityEncryption_v1
      System.arraycopy(layerBytes, 0, out, 1, layerBytes.length)
      out

  /** Decrypt with the recipient's hybrid secret bundle. HNDL-
   *  resistance inherits from `HybridOnion.decrypt` (FR-006). All
   *  per-call failures collapse to typed errors; no exception
   *  thrown.
   */
  def decrypt(
    secret: HybridOnion.HybridSecretBundle,
    ct:     IdentityCiphertext,
  ): Either[IdentityEncError, Array[Byte]] =
    if ct.length < 1 + 1137 then Left(IdentityEncError.InvalidLength)
    else if ct(0) != AlgorithmID.IdentityEncryption_v1 then
      // Uniform refusal per FR-011: no per-ID logging, no variance.
      Left(IdentityEncError.UnsupportedAlgorithm)
    else
      val layerBytes = java.util.Arrays.copyOfRange(ct, 1, ct.length)
      HybridOnion.deserialiseLayer(layerBytes) match
        case Left(_)      => Left(IdentityEncError.MalformedCiphertext("layer deserialise failed"))
        case Right(layer) =>
          HybridOnion.decrypt(secret, layer) match
            case Right(plain) => Right(plain)
            case Left(_)      => Left(IdentityEncError.DecapsulationFailed)

  // ── Serialisation ─────────────────────────────────────────────

  def serialiseCiphertext(ct: IdentityCiphertext): Array[Byte] = ct.clone()

  def deserialiseCiphertext(bytes: Array[Byte]): Either[IdentityEncError, IdentityCiphertext] =
    if bytes.length < 1 + 1137 then Left(IdentityEncError.InvalidLength)
    else if bytes(0) != AlgorithmID.IdentityEncryption_v1 then
      Left(IdentityEncError.UnsupportedAlgorithm)
    else Right(bytes.clone())


/** PKG-directory abstraction. Spec 005 (PKG) provides the
 *  persistent / network-backed implementation; 015 defines the
 *  trait and a tiny in-memory implementation for tests.
 *
 *  Implementations MUST verify the `MultiSignedEntry` proof
 *  bundled with every entry against the PKG roster + threshold +
 *  domain-separation tag the directory was constructed with.
 *  Callers can rely on `lookup`'s `Right` path being a trusted
 *  identity-to-bundle binding.
 */
trait Directory:

  def lookup(identity: Array[Byte]): Either[IdentityEncError, HybridOnion.HybridPublicBundle]


object Directory:

  /** A simple in-memory directory backed by a `Map`. Entries are
   *  passed as `(bundle, MultiSignedEntry)` pairs; the directory
   *  verifies each entry's proof against `roster`, `threshold`,
   *  and `domainSeparationTag` at lookup time (NOT at construction
   *  time, so the verifier behaviour is testable on tampered
   *  entries).
   */
  def inMemory(
    entries:             Map[IArray[Byte], (HybridOnion.HybridPublicBundle, MultiSignedEntry.Entry)],
    roster:              Seq[PqSignature.PqPublicKey],
    threshold:           Int,
    domainSeparationTag: Array[Byte],
  ): Directory =
    new InMemoryDirectory(entries, roster, threshold, domainSeparationTag)

  private final class InMemoryDirectory(
    entries:             Map[IArray[Byte], (HybridOnion.HybridPublicBundle, MultiSignedEntry.Entry)],
    roster:              Seq[PqSignature.PqPublicKey],
    threshold:           Int,
    domainSeparationTag: Array[Byte],
  ) extends Directory:

    def lookup(identity: Array[Byte]): Either[IdentityEncError, HybridOnion.HybridPublicBundle] =
      // IArray-keyed map: convert both sides to ArraySeq for
      // structural equality (Array's default `==` is reference
      // equality). We avoid IArray.toArray (deprecated in Scala 3)
      // by going through IArray.genericWrapArray.
      val key = scala.collection.immutable.ArraySeq.unsafeWrapArray(identity)
      val found = entries.find { case (k, _) =>
        IArray.genericWrapArray(k) == key
      }
      found match
        case None => Left(IdentityEncError.IdentityNotFound)
        case Some((_, (bundle, proof))) =>
          MultiSignedEntry.verify(roster, threshold, domainSeparationTag, proof) match
            case VerifyResult.Valid => Right(bundle)
            case _                  => Left(IdentityEncError.InvalidDirectorySignature)
