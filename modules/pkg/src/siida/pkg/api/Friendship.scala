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
import siida.crypto.api.{Directory, HybridOnion, IdentityEncError}

/** Alpenhorn-style add-request primitive — the "alice → bob,
 *  I want to befriend you" half of friend discovery.
 *
 *  Alice constructs an `AddRequest` ciphertext claiming her
 *  identity + public bundle, encrypted to bob's bundle. Bob
 *  decrypts and verifies the claim against his current PKG
 *  directory snapshot. Verified add-requests land in bob's
 *  local `FriendStore` (caller's responsibility to add).
 *
 *  See spec 019-friend-discovery for the full design. Mixnet
 *  routing, cover-add-traffic, add-response, and friendship-key
 *  dial tokens are out-of-scope of this MVP.
 */
object Friendship:

  opaque type AddRequest = Array[Byte]

  object AlgorithmID:
    val AddRequest_v1: Byte = 0x30.toByte

  final case class AddRequestContent(
    senderIdentity:     Array[Byte],
    senderPublicBundle: HybridOnion.HybridPublicBundle,
  )

  // ── Construction ───────────────────────────────────────────────

  /** Alice builds an add-request to bob. Pack alice's identity +
   *  her public bundle as the plaintext; encrypt under bob's
   *  bundle via HybridOnion; prefix with the 0x30 algorithm-ID.
   */
  def buildAddRequest(
    senderIdentity:        Array[Byte],
    senderPublicBundle:    HybridOnion.HybridPublicBundle,
    recipientPublicBundle: HybridOnion.HybridPublicBundle,
    rng:                   SecureRandom,
  ): AddRequest =
    val payload = AddRequestWire.encode(senderIdentity, senderPublicBundle)
    val layer = HybridOnion.encrypt(recipientPublicBundle, payload, rng)
    val layerBytes = HybridOnion.serialiseLayer(layer)
    val out = new Array[Byte](1 + layerBytes.length)
    out(0) = AlgorithmID.AddRequest_v1
    System.arraycopy(layerBytes, 0, out, 1, layerBytes.length)
    out

  // ── Processing ─────────────────────────────────────────────────

  /** Bob receives an add-request, decrypts with his secret bundle,
   *  and recovers the claimed content. Per FR-006, all per-call
   *  failures collapse to typed `FriendshipError`s.
   *
   *  This step is CRYPTOGRAPHIC verification only — the content
   *  is still untrusted at this point because anyone could have
   *  encrypted to bob's public bundle. The trust step is
   *  `verifyAddRequest`.
   */
  def processAddRequest(
    recipientSecret: HybridOnion.HybridSecretBundle,
    ct:              AddRequest,
  ): Either[FriendshipError, AddRequestContent] =
    if ct.length < 1 + 1137 then Left(FriendshipError.InvalidLength)
    else if ct(0) != AlgorithmID.AddRequest_v1 then
      Left(FriendshipError.UnsupportedAlgorithm)
    else
      val layerBytes = java.util.Arrays.copyOfRange(ct, 1, ct.length)
      HybridOnion.deserialiseLayer(layerBytes) match
        case Left(_)      => Left(FriendshipError.MalformedRequest("layer deserialise failed"))
        case Right(layer) =>
          HybridOnion.decrypt(recipientSecret, layer) match
            case Left(_)      => Left(FriendshipError.DecryptionFailed)
            case Right(plain) =>
              AddRequestWire.decode(plain) match
                case None              => Left(FriendshipError.MalformedRequest("payload decode failed"))
                case Some((id, bundle)) => Right(AddRequestContent(id, bundle))

  // ── Verification (the load-bearing trust step — SC-006) ─────────

  /** Verify that the claimed `senderIdentity` actually maps to
   *  the claimed `senderPublicBundle` in the directory. This is
   *  the trust hinge: if the directory's binding disagrees with
   *  the ciphertext's self-claim, the request is forged.
   */
  def verifyAddRequest(
    content:   AddRequestContent,
    directory: Directory,
  ): Either[FriendshipError, Unit] =
    directory.lookup(content.senderIdentity) match
      case Left(IdentityEncError.IdentityNotFound) =>
        Left(FriendshipError.IdentityNotInDirectory)
      case Left(_) =>
        // Directory signature failure, etc. — treat as "not in directory"
        // for the friendship caller. The SDK should refresh the snapshot.
        Left(FriendshipError.IdentityNotInDirectory)
      case Right(dirBundle) =>
        val claimedBytes = HybridOnion.serialisePublicBundle(content.senderPublicBundle)
        val dirBytes     = HybridOnion.serialisePublicBundle(dirBundle)
        if java.util.Arrays.equals(claimedBytes, dirBytes) then Right(())
        else Left(FriendshipError.IdentityMismatch)

  // ── Serialisation ─────────────────────────────────────────────

  def serialiseAddRequest(req: AddRequest): Array[Byte] = req.clone()

  def deserialiseAddRequest(bytes: Array[Byte]): Either[FriendshipError, AddRequest] =
    if bytes.length < 1 + 1137 then Left(FriendshipError.InvalidLength)
    else if bytes(0) != AlgorithmID.AddRequest_v1 then
      Left(FriendshipError.UnsupportedAlgorithm)
    else Right(bytes.clone())
