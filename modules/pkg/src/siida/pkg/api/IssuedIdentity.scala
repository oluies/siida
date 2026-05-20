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

import siida.crypto.api.{HybridOnion, MultiSignedEntry}

/** The PKG's response to a successful `issueIdentity` call.
 *
 *  - `secretBundle` is the user's to hold (delivered out-of-band).
 *    The PKG does NOT retain it (SC-006).
 *  - `mailboxId` is the per-identity routing key into the dead-
 *    drop store (spec 004's space, with reserved IDs skipped).
 *  - `publicBundle` and `proof` are echoed back for the caller's
 *    verification convenience; both are also stored in the PKG's
 *    directory for future `lookup` calls.
 */
final case class IssuedIdentity(
  secretBundle: HybridOnion.HybridSecretBundle,
  mailboxId:    Long,
  publicBundle: HybridOnion.HybridPublicBundle,
  proof:        MultiSignedEntry.Entry,
)
