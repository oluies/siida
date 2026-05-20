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

/** Typed errors returned by `SiidaClient`.
 *
 *  Distinct from underlying primitive errors (HybridOnionError,
 *  FriendshipError, IdentityEncError) because the SDK is the layer
 *  that decides "what does the user see when X fails"; the
 *  conversion happens at the SDK boundary.
 */
enum SdkError derives CanEqual:
  case IdentityNotInDirectory
  case BadDirectoryProof
  case WrongMailbox
  case UnsupportedSdkType
  case DecryptionFailed
  case MalformedEnvelope(reason: String)
  case AddRequestVerificationFailed
  case InternalError(reason: String)
