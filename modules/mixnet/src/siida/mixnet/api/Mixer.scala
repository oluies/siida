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

package siida.mixnet.api

import siida.crypto.api.HybridOnion

/** Mixer primitives: peel exactly one layer from an `OnionLayer`.
 *  A mixer is otherwise stateless — its only persistent state is
 *  its `HybridSecretBundle`, which is held by the operator and
 *  passed to `peel` per call.
 */
object Mixer:

  /** Decrypt one layer of the onion. Returns the inner bytes — the
   *  caller (coordinator) interprets them as either the next-layer
   *  OnionLayer or, if this mixer is the last in the chain, as the
   *  innermost MailboxEnvelope.
   *
   *  Returns `None` on any per-call failure (decryption error,
   *  malformed wire bytes). Per FR-004, mixers silently drop
   *  failing submissions to avoid fingerprinting the batch.
   */
  def peel(
    secret: HybridOnion.HybridSecretBundle,
    layer:  HybridOnion.OnionLayer,
  ): Option[Array[Byte]] =
    HybridOnion.decrypt(secret, layer) match
      case Right(inner) => Some(inner)
      case Left(_)      => None
