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

package siida.configchain.api

/** Typed errors returned by ConfigChain operations (spec 006).
 *
 *  All append-time outcomes (other than "everything OK") collapse
 *  here so callers can pattern-match exhaustively under
 *  `-Werror -language:strictEquality`.
 */
enum ConfigChainError derives CanEqual:
  case InvalidPayload(reason: String)
  case UnsupportedVersion
  case GenesisAlreadyEstablished
  case WrongPredecessor
  case EpochNotMonotonic(expected: Long, found: Long)
  case ThresholdNotMet(validCount: Int, required: Int)
  case AlreadyApplied
  case BadRoster(reason: String)
  case BadThreshold(reason: String)
  case MalformedEntry(reason: String)
