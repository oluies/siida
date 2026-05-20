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

package siida.sdk.api

import siida.crypto.api.HybridOnion

/** SDK-side view of "where to send a message to a known identity":
 *  produces both the verified `HybridPublicBundle` (for e2e encrypt)
 *  AND the recipient's mailbox id (for envelope routing).
 *
 *  Construction-time impls SHOULD verify each entry's MultiSignedEntry
 *  proof against the configured chain so the `Right` path is a
 *  trusted (identity → bundle + mailbox) binding.
 */
trait PeerCatalog:

  def lookup(identity: Array[Byte]): Either[SdkError, PeerCatalog.Peer]


object PeerCatalog:

  final case class Peer(
    publicBundle: HybridOnion.HybridPublicBundle,
    mailboxId:    Long,
  )

  /** Pre-verified in-memory catalog. Useful for tests and for SDK
   *  consumers that have already validated entries themselves
   *  (e.g. via [[siida.crypto.api.Directory]] + [[siida.configchain.api.ConfigChain]]).
   *
   *  The map is keyed by an `IArray[Byte]` of the identity bytes.
   *  Internally a wrapper provides structural equality.
   */
  def inMemoryVerified(
    entries: Map[IArray[Byte], Peer],
  ): PeerCatalog = new InMemoryPeerCatalog(entries)

  private final class InMemoryPeerCatalog(
    entries: Map[IArray[Byte], Peer],
  ) extends PeerCatalog:

    def lookup(identity: Array[Byte]): Either[SdkError, Peer] =
      val key = scala.collection.immutable.ArraySeq.unsafeWrapArray(identity)
      val found = entries.find { case (k, _) =>
        IArray.genericWrapArray(k) == key
      }
      found match
        case None         => Left(SdkError.IdentityNotInDirectory)
        case Some((_, p)) => Right(p)
