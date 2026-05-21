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

import siida.crypto.api.{HybridOnion, PqSignature}

/** Local cache of accepted friend identities → their public
 *  bundles. The SDK (spec 007) consults this before falling
 *  back to a PKG-directory lookup; misses in the FriendStore
 *  result in directory-revealing lookups.
 *
 *  Spec 019-friend-discovery MVP: in-memory only. Persistent
 *  encrypted-at-rest storage is a follow-up spec.
 */
trait FriendStore:

  /** Add an accepted friend. Returns `false` if the identity was
   *  already present (idempotent re-add — does NOT replace the
   *  bundle); `true` if newly added.
   */
  def add(
    identity: Array[Byte],
    bundle:   HybridOnion.HybridPublicBundle,
  ): Boolean

  def lookup(identity: Array[Byte]): Option[HybridOnion.HybridPublicBundle]

  /** Enumerate the identities currently in the store. Order is
   *  insertion order (LinkedHashMap-backed).
   */
  def list(): Seq[Array[Byte]]

  /** Spec 027: register a friend together with the signing key used
   *  to verify their signed-chat envelopes. Returns false if the
   *  identity is already present; in that case the existing entry
   *  is left untouched (idempotent re-add).
   */
  def addWithSigningKey(
    identity: Array[Byte],
    bundle:   HybridOnion.HybridPublicBundle,
    sigPk:    PqSignature.PqPublicKey,
  ): Boolean

  /** Spec 027: look up the signing key for a registered friend.
   *  Returns `None` if the identity is unknown OR if the entry
   *  was added without a signing key (e.g. via the legacy
   *  `add(identity, bundle)` path, or by the persistent
   *  FriendStore — its on-disk format does not yet carry
   *  signing keys).
   */
  def lookupSigningKey(identity: Array[Byte]): Option[PqSignature.PqPublicKey]


object FriendStore:

  def inMemory(): FriendStore = new InMemoryFriendStore()

  /** Persistent FriendStore (spec 020 US3). On-disk file at `path`
   *  containing the friend identities and their bundles. Per FR-004
   *  the file is atomically rewritten on every `add` (write-tmp +
   *  rename) so a crash mid-add cannot corrupt the existing store.
   *
   *  Wire format:
   *  ```
   *  offset  size  field
   *  0       4     magic "SIFD" (0x53 0x49 0x46 0x44)
   *  4       N     repeating records:
   *    2     identity_len (uint16 BE)
   *    L     identity_bytes
   *    1216  bundle_bytes (HybridOnion.serialisePublicBundle)
   *  ```
   *
   *  Concurrent writers on the same path are NOT supported; the
   *  caller is responsible for single-writer discipline.
   */
  def persistent(path: java.nio.file.Path): Either[String, FriendStore] =
    PersistentFriendStore.openOrCreate(path)

  private final class InMemoryFriendStore extends FriendStore:

    // Identity bytes wrapped in an ArraySeq so structural
    // equality works (Array's default `==` is reference).
    private val entries =
      scala.collection.mutable.LinkedHashMap.empty[
        scala.collection.immutable.ArraySeq[Byte],
        HybridOnion.HybridPublicBundle,
      ]

    private val signingKeys =
      scala.collection.mutable.HashMap.empty[
        scala.collection.immutable.ArraySeq[Byte],
        PqSignature.PqPublicKey,
      ]

    def add(identity: Array[Byte], bundle: HybridOnion.HybridPublicBundle): Boolean =
      val key = scala.collection.immutable.ArraySeq.unsafeWrapArray(identity.clone())
      if entries.contains(key) then false
      else
        entries.update(key, bundle)
        true

    def addWithSigningKey(
      identity: Array[Byte],
      bundle:   HybridOnion.HybridPublicBundle,
      sigPk:    PqSignature.PqPublicKey,
    ): Boolean =
      val key = scala.collection.immutable.ArraySeq.unsafeWrapArray(identity.clone())
      if entries.contains(key) then false
      else
        entries.update(key, bundle)
        signingKeys.update(key, sigPk)
        true

    def lookup(identity: Array[Byte]): Option[HybridOnion.HybridPublicBundle] =
      val key = scala.collection.immutable.ArraySeq.unsafeWrapArray(identity)
      entries.get(key)

    def lookupSigningKey(identity: Array[Byte]): Option[PqSignature.PqPublicKey] =
      val key = scala.collection.immutable.ArraySeq.unsafeWrapArray(identity)
      signingKeys.get(key)

    def list(): Seq[Array[Byte]] =
      entries.keys.iterator.map(_.toArray).toVector
