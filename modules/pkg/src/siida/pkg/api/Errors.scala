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

/** Typed errors returned by the PKG public API. */
enum PkgError derives CanEqual:
  case EmptyRoster
  case InvalidThreshold(threshold: Int, rosterSize: Int)
  case RosterKeyMismatch(have: Int, expected: Int)
  case IdentityAlreadyExists
  case MailboxIdExhausted

/** Typed errors returned by the Friendship public API (spec
 *  019-friend-discovery). All per-call failures are typed; no
 *  throws on per-call paths.
 */
enum FriendshipError derives CanEqual:
  case InvalidLength
  case UnsupportedAlgorithm
  case DecryptionFailed
  case MalformedRequest(reason: String)
  case IdentityNotInDirectory
  case IdentityMismatch
