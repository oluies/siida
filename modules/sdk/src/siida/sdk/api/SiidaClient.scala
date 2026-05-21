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

import java.security.SecureRandom
import siida.crypto.api.{HybridOnion, HybridOnionError}
import siida.mixnet.api.MixChain
import siida.pkg.api.{Friendship, FriendshipError}

/** End-user-facing client SDK (spec 007 MVP — local composition).
 *
 *  Composes the cryptographic primitives, mailbox envelopes, and the
 *  mix chain into the two flows a user cares about:
 *  - sendChatMessage(identity, payload, rng)
 *  - sendAddRequest(identity, rng)
 *  - deliver(mailbox-envelope bytes) → IncomingMessage
 *  - coverSubmission(payloadLen, rng)
 *
 *  No network transport (that's spec 009). The client produces the
 *  bytes that go on the wire; the caller hands those bytes to the
 *  mixnet round coordinator.
 */
trait SiidaClient:

  /** This client's own identity bytes (as registered with the PKG). */
  def identity: Array[Byte]

  /** This client's own mailbox id at the last mixer. */
  def mailboxId: Long

  /** Build a layered submission carrying a chat message to
   *  `recipientIdentity`. Returns the OnionLayer ready to feed into
   *  the mixnet round.
   */
  def sendChatMessage(
    recipientIdentity: Array[Byte],
    payload:           Array[Byte],
    rng:               SecureRandom,
  ): Either[SdkError, HybridOnion.OnionLayer]

  /** Build a layered submission carrying an authenticated chat
   *  message (spec 023). Inner payload is
   *  `(2B sender_id_len, sender_id_bytes, chat_payload)`, e2e-
   *  encrypted to the recipient's bundle. The receiver gets the
   *  sender's identity bytes back via `IncomingMessage.AuthenticatedChat`.
   */
  def sendAuthenticatedChatMessage(
    recipientIdentity: Array[Byte],
    payload:           Array[Byte],
    rng:               SecureRandom,
  ): Either[SdkError, HybridOnion.OnionLayer]

  /** Build a layered submission carrying an Alpenhorn add-request to
   *  `recipientIdentity`. The add-request's content is THIS client's
   *  identity + public bundle, end-to-end encrypted via the spec 019
   *  Friendship primitive against the recipient's directory binding.
   */
  def sendAddRequest(
    recipientIdentity: Array[Byte],
    rng:               SecureRandom,
  ): Either[SdkError, HybridOnion.OnionLayer]

  /** Cover-traffic submission (FR-007). Indistinguishable on the
   *  wire from a real submission of the same payload length.
   */
  def coverSubmission(
    payloadLen: Int,
    rng:        SecureRandom,
  ): HybridOnion.OnionLayer

  /** Process a MailboxEnvelope cleartext payload that the mixnet
   *  delivered for THIS client's mailbox. Decrypts, peels the SDK
   *  type byte, and surfaces a typed `IncomingMessage`.
   */
  def deliver(
    envelopeBytes: Array[Byte],
  ): Either[SdkError, SiidaClient.IncomingMessage]


object SiidaClient:

  /** Result of a successful `deliver`. */
  enum IncomingMessage derives CanEqual:
    case ChatMessage(payload: Array[Byte])
    case AddRequest(content: Friendship.AddRequestContent)
    /** Spec 023: authenticated chat. `senderIdentity` is the sender's
     *  identity bytes as transcribed from the wire (NOT verified
     *  cryptographically here — see spec for the trust model).
     */
    case AuthenticatedChat(senderIdentity: Array[Byte], payload: Array[Byte])

  /** Build a local-composition client. No network transport —
   *  callers feed the produced OnionLayer to the mixnet round
   *  themselves (the Coordinator from spec 004).
   *
   *  @param identity            this client's identity bytes
   *  @param secretBundle        this client's HybridSecretBundle (for delivery)
   *  @param myPublicBundle      this client's public bundle (sent in add-requests)
   *  @param myMailboxId         this client's mailbox id
   *  @param mixChainPublicBundles the mixer chain (innermost → outermost) used for layered submission
   *  @param peerCatalog         lookup for "where is recipient X" — bundle + mailbox id
   */
  def create(
    identity:              Array[Byte],
    secretBundle:          HybridOnion.HybridSecretBundle,
    myPublicBundle:        HybridOnion.HybridPublicBundle,
    myMailboxId:           Long,
    mixChainPublicBundles: Seq[HybridOnion.HybridPublicBundle],
    peerCatalog:           PeerCatalog,
  ): SiidaClient =
    require(mixChainPublicBundles.nonEmpty,
      "SiidaClient.create: mix chain must be non-empty")
    new LocalSiidaClient(
      identity.clone(),
      secretBundle,
      myPublicBundle,
      myMailboxId,
      mixChainPublicBundles.toVector,
      peerCatalog,
    )

  private final class LocalSiidaClient(
    private val identityBytes:    Array[Byte],
    private val secretBundle:     HybridOnion.HybridSecretBundle,
    private val myPublicBundle:   HybridOnion.HybridPublicBundle,
    private val myMailboxId_     : Long,
    private val mixChain:         Vector[HybridOnion.HybridPublicBundle],
    private val catalog:          PeerCatalog,
  ) extends SiidaClient:

    def identity: Array[Byte] = identityBytes.clone()
    def mailboxId: Long       = myMailboxId_

    def sendChatMessage(
      recipientIdentity: Array[Byte],
      payload:           Array[Byte],
      rng:               SecureRandom,
    ): Either[SdkError, HybridOnion.OnionLayer] =
      catalog.lookup(recipientIdentity).map { peer =>
        // 1. End-to-end encrypt the chat payload to the recipient's
        //    HybridPublicBundle (the chat-message inner content IS
        //    the serialised OnionLayer)
        val e2e = HybridOnion.encrypt(peer.publicBundle, payload, rng)
        val inner = HybridOnion.serialiseLayer(e2e)
        // 2. SDK-wrap with the type byte
        val sdkPayload = SdkEnvelope.wrap(SdkEnvelope.Type.ChatMessage, inner)
        // 3. Build the MailboxEnvelope addressed to the recipient
        val env = MixChain.envelope(peer.mailboxId, sdkPayload)
        // 4. Layered-encrypt through the mix chain
        MixChain.layeredSubmission(mixChain, env, rng)
      }

    def sendAuthenticatedChatMessage(
      recipientIdentity: Array[Byte],
      payload:           Array[Byte],
      rng:               SecureRandom,
    ): Either[SdkError, HybridOnion.OnionLayer] =
      catalog.lookup(recipientIdentity).map { peer =>
        // 1. Build the inner-payload (sender identity + chat)
        val authPayload = AuthenticatedChatWire.encode(identityBytes, payload)
        // 2. End-to-end encrypt to the recipient's bundle
        val e2e = HybridOnion.encrypt(peer.publicBundle, authPayload, rng)
        val inner = HybridOnion.serialiseLayer(e2e)
        // 3. SDK-wrap with the new type byte
        val sdkPayload = SdkEnvelope.wrap(SdkEnvelope.Type.AuthenticatedChat, inner)
        // 4. MailboxEnvelope + layered submission
        val env = MixChain.envelope(peer.mailboxId, sdkPayload)
        MixChain.layeredSubmission(mixChain, env, rng)
      }

    def sendAddRequest(
      recipientIdentity: Array[Byte],
      rng:               SecureRandom,
    ): Either[SdkError, HybridOnion.OnionLayer] =
      catalog.lookup(recipientIdentity).map { peer =>
        // 1. Build the Friendship add-request (e2e encrypted under
        //    the hood) — sender identity + sender public bundle
        val addReq = Friendship.buildAddRequest(
          identityBytes,
          myPublicBundle,
          peer.publicBundle,
          rng,
        )
        val inner = Friendship.serialiseAddRequest(addReq)
        // 2. SDK-wrap
        val sdkPayload = SdkEnvelope.wrap(SdkEnvelope.Type.AddRequest, inner)
        // 3. MailboxEnvelope + layered submission
        val env = MixChain.envelope(peer.mailboxId, sdkPayload)
        MixChain.layeredSubmission(mixChain, env, rng)
      }

    def coverSubmission(payloadLen: Int, rng: SecureRandom): HybridOnion.OnionLayer =
      MixChain.coverSubmission(mixChain, payloadLen, rng)

    def deliver(envelopeBytes: Array[Byte]): Either[SdkError, IncomingMessage] =
      MixChain.deserialiseEnvelope(envelopeBytes).left.map { err =>
        SdkError.MalformedEnvelope(s"envelope deserialisation: $err")
      }.flatMap { env =>
        val envMailbox = MixChain.envelopeMailboxId(env)
        if envMailbox != myMailboxId_ then
          Left(SdkError.WrongMailbox)
        else
          val sdkPayload = MixChain.envelopePayload(env)
          SdkEnvelope.parse(sdkPayload).flatMap { case (typ, inner) =>
            if typ == SdkEnvelope.Type.ChatMessage then
              decryptChat(inner)
            else if typ == SdkEnvelope.Type.AddRequest then
              processAddRequest(inner)
            else if typ == SdkEnvelope.Type.AuthenticatedChat then
              decryptAuthenticatedChat(inner)
            else
              Left(SdkError.UnsupportedSdkType)
          }
      }

    private def decryptChat(layerBytes: Array[Byte]): Either[SdkError, IncomingMessage] =
      HybridOnion.deserialiseLayer(layerBytes).left.map(toSdk).flatMap { layer =>
        HybridOnion.decrypt(secretBundle, layer).left.map(toSdk).map { plaintext =>
          IncomingMessage.ChatMessage(plaintext)
        }
      }

    private def decryptAuthenticatedChat(layerBytes: Array[Byte]): Either[SdkError, IncomingMessage] =
      HybridOnion.deserialiseLayer(layerBytes).left.map(toSdk).flatMap { layer =>
        HybridOnion.decrypt(secretBundle, layer).left.map(toSdk).flatMap { plaintext =>
          AuthenticatedChatWire.decode(plaintext).map { case (senderId, payload) =>
            IncomingMessage.AuthenticatedChat(senderId, payload)
          }
        }
      }

    private def processAddRequest(addReqBytes: Array[Byte]): Either[SdkError, IncomingMessage] =
      Friendship.deserialiseAddRequest(addReqBytes).left.map { _ =>
        SdkError.MalformedEnvelope("add-request deserialisation failed")
      }.flatMap { req =>
        Friendship.processAddRequest(secretBundle, req).left.map { err =>
          friendshipToSdk(err)
        }.map(IncomingMessage.AddRequest.apply)
      }

    private def toSdk(err: HybridOnionError): SdkError = err match
      case HybridOnionError.DecapsulationFailed       => SdkError.DecryptionFailed
      case HybridOnionError.InvalidLength             => SdkError.MalformedEnvelope("invalid length")
      case HybridOnionError.UnsupportedAlgorithm      => SdkError.MalformedEnvelope("unsupported algorithm")
      case HybridOnionError.MalformedCiphertext(r)    => SdkError.MalformedEnvelope(r)
      case HybridOnionError.IncompleteBundle          => SdkError.MalformedEnvelope("incomplete bundle")
      case HybridOnionError.InvalidPoint              => SdkError.MalformedEnvelope("invalid point")

    private def friendshipToSdk(err: FriendshipError): SdkError = err match
      case FriendshipError.DecryptionFailed             => SdkError.DecryptionFailed
      case FriendshipError.InvalidLength                => SdkError.MalformedEnvelope("friendship: invalid length")
      case FriendshipError.UnsupportedAlgorithm         => SdkError.UnsupportedSdkType
      case FriendshipError.MalformedRequest(r)          => SdkError.MalformedEnvelope(s"friendship: $r")
      case FriendshipError.IdentityNotInDirectory       => SdkError.AddRequestVerificationFailed
      case FriendshipError.IdentityMismatch             => SdkError.AddRequestVerificationFailed
