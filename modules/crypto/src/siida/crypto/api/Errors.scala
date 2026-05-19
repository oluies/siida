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

/** Typed errors returned by the IBE public API. Per FR-005,
 *  expected failure modes (malformed input, wrong-identity
 *  decryption) return Left(IBEError) rather than throwing.
 */
enum IBEError derives CanEqual:
  case InvalidKey
  case InvalidPoint
  case MalformedCiphertext(reason: String)
  case WrongIdentity
  case DecryptionFailed

/** Typed errors returned by the BLS public API. */
enum BLSError derives CanEqual:
  case InvalidKey
  case InvalidPoint
  case InvalidSignature
  case InvalidPOP
  case EmptyAggregation
  case DistinctMessageRequired

/** Typed errors returned by the BN254 lower-level API
 *  (deserialisation paths). On-curve and subgroup checks happen at
 *  every deserialise call.
 */
enum BN254Error derives CanEqual:
  case InvalidEncoding
  case PointNotOnCurve
  case PointNotInSubgroup
  case InvalidLength
  case Internal(reason: String)

/** Exception raised at JVM startup when the native shim cannot be
 *  loaded. Distinct from BN254Error because the failure mode is
 *  programming-environment, not per-call. See
 *  `siida.crypto.internal.NativeLoader`.
 */
final class UnsupportedNativeArchException(msg: String)
    extends RuntimeException(msg)
