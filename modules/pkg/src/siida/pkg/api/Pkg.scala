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

package siida.pkg.api

import java.security.SecureRandom
import siida.crypto.api.{Directory, HybridOnion, MultiSignedEntry, PqSignature}
import siida.mixnet.api.MixChain
import siida.observability.api.Telemetry

/** Spec 005-pkg-keybootstrap — the Private Key Generator.
 *
 *  Holds an M-of-N roster of ML-DSA-65 keys; issues fresh
 *  HybridOnion bundles per identity; signs `(identity, mailbox_id,
 *  public_bundle)` bindings via MultiSignedEntry; exposes the
 *  accumulated directory as `IdentityEncryption.Directory` for
 *  015's encryption flow.
 *
 *  MVP — in-memory only, no friend-discovery, no roster rotation.
 *  See spec.md for explicit out-of-scope list.
 */
trait Pkg:

  def issueIdentity(
    identity: Array[Byte],
    rng:      SecureRandom,
  ): Either[PkgError, IssuedIdentity]

  def directorySnapshot(): Directory


object Pkg:

  /** Build a PKG. Validates the configuration (non-empty roster,
   *  threshold ≤ roster size, roster key-pair count match). The
   *  PKG's signing strategy is "first `threshold` signers in
   *  roster order" — see research R4 for the MVP rationale.
   */
  def create(
    rosterPublicKeys:    Seq[PqSignature.PqPublicKey],
    rosterPrivateKeys:   Seq[PqSignature.PqPrivateKey],
    threshold:           Int,
    domainSeparationTag: Array[Byte],
    initialMailboxId:    Long = 1L,
    telemetry:           Telemetry = Telemetry.noop,
  ): Either[PkgError, Pkg] =
    if rosterPublicKeys.isEmpty || rosterPrivateKeys.isEmpty then
      Left(PkgError.EmptyRoster)
    else if rosterPublicKeys.length != rosterPrivateKeys.length then
      Left(PkgError.RosterKeyMismatch(
        rosterPrivateKeys.length, rosterPublicKeys.length))
    else if threshold <= 0 || threshold > rosterPublicKeys.length then
      Left(PkgError.InvalidThreshold(threshold, rosterPublicKeys.length))
    else
      Right(new InMemoryPkg(
        rosterPublicKeys.toVector,
        rosterPrivateKeys.toVector,
        threshold,
        domainSeparationTag.clone(),
        initialMailboxId,
        telemetry,
      ))

  private final class InMemoryPkg(
    rosterPublicKeys:    Vector[PqSignature.PqPublicKey],
    rosterPrivateKeys:   Vector[PqSignature.PqPrivateKey],
    threshold:           Int,
    domainSeparationTag: Array[Byte],
    initialMailboxId:    Long,
    telemetry:           Telemetry,
  ) extends Pkg:

    // Identity → (publicBundle, mailboxId, proof). Bytes-keyed via
    // ArraySeq wrapper because Array[Byte] equality is reference.
    private val entries = scala.collection.mutable.LinkedHashMap.empty[
      scala.collection.immutable.ArraySeq[Byte],
      (HybridOnion.HybridPublicBundle, Long, MultiSignedEntry.Entry),
    ]

    private var nextMailboxId: Long = initialMailboxId

    /** Advance the mailbox-id allocator past reserved values. */
    private def allocateMailboxId(): Long =
      while nextMailboxId == MixChain.CoverMailboxId
         || nextMailboxId == MixChain.BroadcastMailboxId do
        nextMailboxId += 1
      val out = nextMailboxId
      nextMailboxId += 1
      out

    def issueIdentity(
      identity: Array[Byte],
      rng:      SecureRandom,
    ): Either[PkgError, IssuedIdentity] =
      val key = scala.collection.immutable.ArraySeq.unsafeWrapArray(identity.clone())
      if entries.contains(key) then
        telemetry.incrementCounter("pkg.identity.rejected_duplicate", 1L)
        Left(PkgError.IdentityAlreadyExists)
      else
        val (secret, public) = HybridOnion.generateBundle(rng)
        val mailboxId = allocateMailboxId()
        val payload = DirectoryEntryWire.encode(identity, mailboxId, public)
        val signedMsg = MultiSignedEntry.signedMessage(payload, domainSeparationTag)
        val sigs = (0 until threshold).map { i =>
          (i, PqSignature.sign(rosterPrivateKeys(i), signedMsg))
        }
        MultiSignedEntry.assemble(payload, sigs) match
          case Left(_) =>
            // Hitting this means the wire-format invariants
            // (signature wire size, etc.) are broken — a real bug,
            // not a per-call failure. Bubble up as a programming
            // error via throw, since PkgError doesn't have a slot
            // for "MultiSignedEntry.assemble broke."
            throw RuntimeException("PKG: MultiSignedEntry.assemble failed unexpectedly")
          case Right(entry) =>
            entries.update(key, (public, mailboxId, entry))
            telemetry.incrementCounter("pkg.identity.issued", 1L)
            telemetry.recordGauge("pkg.directory.size", entries.size.toDouble)
            Right(IssuedIdentity(
              secretBundle = secret,
              mailboxId    = mailboxId,
              publicBundle = public,
              proof        = entry,
            ))

    def directorySnapshot(): Directory =
      // Build a snapshot Map keyed by IArray[Byte] (the type
      // accepted by Directory.inMemory). The snapshot reflects
      // the directory state at this method call; subsequent
      // issuances after this call don't appear (until the SDK
      // re-fetches a snapshot).
      val snapshotEntries: Map[IArray[Byte], (HybridOnion.HybridPublicBundle, MultiSignedEntry.Entry)] =
        entries.iterator.map { case (key, (bundle, _, proof)) =>
          val asArray: IArray[Byte] = IArray.unsafeFromArray(key.toArray)
          asArray -> ((bundle, proof))
        }.toMap
      Directory.inMemory(
        snapshotEntries,
        rosterPublicKeys,
        threshold,
        domainSeparationTag,
      )
