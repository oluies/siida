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

/** Typed errors surfaced by the mixnet public API. Per spec 004,
 *  per-call failures (a single submission failing to decrypt at a
 *  mixer) do NOT raise these — they're silently dropped (FR-004).
 *  These errors are reserved for programming-level violations
 *  detected at API boundaries: chain-length mismatches, wrong-sized
 *  shuffle seeds, malformed envelopes.
 */
enum MixnetError derives CanEqual:
  case InvalidLength
  case MalformedEnvelope(reason: String)
  case ChainLengthMismatch(have: Int, want: Int)
  case ShuffleSeedSize(have: Int, want: Int)
