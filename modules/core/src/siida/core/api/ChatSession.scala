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

package siida.core.api

import java.security.SecureRandom
import siida.crypto.api.HybridOnion
import siida.pkg.api.{Friendship, FriendStore}
import siida.sdk.api.{SdkError, SiidaClient}

/** Headless chat-session model (spec 010 MVP). Aggregates a
 *  `SiidaClient` and a `FriendStore` into a single object UI
 *  layers (TUI, GUI, web) drive.
 *
 *  No UI here — the caller renders the `history` and dispatches
 *  outbound `OnionLayer`s to the mixnet round.
 */
trait ChatSession:

  def myAlias: String

  /** Compose + send a UTF-8 text message to a friend by alias. */
  def sendChat(
    alias:   String,
    text:    String,
    rng:     SecureRandom,
  ): Either[ChatSession.SessionError, HybridOnion.OnionLayer]

  /** Deliver a mailbox-envelope cleartext (post-mixnet peel) for
   *  this session's mailbox id. Returns a typed event the UI can
   *  render.
   */
  def deliverInbound(
    envelopeBytes: Array[Byte],
  ): Either[ChatSession.SessionError, ChatSession.InboundEvent]

  /** Friend aliases known to this session, insertion order. */
  def friends: Seq[String]

  /** Look up an alias → (identity bytes, bundle). */
  def lookup(alias: String): Option[(Array[Byte], HybridOnion.HybridPublicBundle)]

  /** Append-only chat history (outgoing + delivered inbound). */
  def history: Seq[ChatSession.ChatLine]


object ChatSession:

  enum SessionError derives CanEqual:
    case UnknownFriend(alias: String)
    case NotAddressedToMe
    case DecryptionFailed
    case MalformedEnvelope(reason: String)
    case UnsupportedSdkType
    case SdkError(reason: String)

  enum ChatLine derives CanEqual:
    case Outbound(toAlias: String, text: String)
    case Inbound(fromAlias: String, text: String)

  enum InboundEvent derives CanEqual:
    case Chat(line: ChatLine.Inbound)
    case AddRequest(senderIdentity: Array[Byte])

  def create(
    myAlias:      String,
    siida:        SiidaClient,
    friendStore:  FriendStore,
  ): ChatSession =
    new InMemoryChatSession(myAlias, siida, friendStore)

  private final class InMemoryChatSession(
    myAlias_     : String,
    siida:        SiidaClient,
    friendStore:  FriendStore,
  ) extends ChatSession:

    private val log = scala.collection.mutable.ArrayBuffer.empty[ChatLine]

    def myAlias: String = myAlias_

    def sendChat(
      alias: String,
      text:  String,
      rng:   SecureRandom,
    ): Either[SessionError, HybridOnion.OnionLayer] =
      lookup(alias) match
        case None => Left(SessionError.UnknownFriend(alias))
        case Some((idBytes, _)) =>
          siida.sendChatMessage(idBytes, text.getBytes("UTF-8"), rng) match
            case Right(onion) =>
              log += ChatLine.Outbound(alias, text)
              Right(onion)
            case Left(e) => Left(sdkErrToSession(e))

    def deliverInbound(envelopeBytes: Array[Byte]): Either[SessionError, InboundEvent] =
      siida.deliver(envelopeBytes) match
        case Left(e) => Left(sdkErrToSession(e))
        case Right(SiidaClient.IncomingMessage.ChatMessage(payload)) =>
          val text = new String(payload, "UTF-8")
          // The chat message doesn't carry the sender's identity at
          // the SDK level — it's only the addressed mailbox + the
          // payload. The session can't resolve a sender alias from
          // the wire alone. The friend-discovery / add-request flow
          // is where senders prove identity; in the MVP we surface
          // chat with a placeholder "?" alias unless the calling
          // layer routes the inbound to an expected sender.
          val line: ChatLine.Inbound = ChatLine.Inbound("?", text)
          log += line
          Right(InboundEvent.Chat(line))
        case Right(SiidaClient.IncomingMessage.AddRequest(content)) =>
          Right(InboundEvent.AddRequest(content.senderIdentity))

    def friends: Seq[String] =
      friendStore.list().map(new String(_, "UTF-8"))

    def lookup(alias: String): Option[(Array[Byte], HybridOnion.HybridPublicBundle)] =
      val idBytes = alias.getBytes("UTF-8")
      friendStore.lookup(idBytes).map(b => (idBytes.clone(), b))

    def history: Seq[ChatLine] = log.toVector

    private def sdkErrToSession(e: SdkError): SessionError = e match
      case SdkError.IdentityNotInDirectory       => SessionError.UnknownFriend("(directory)")
      case SdkError.WrongMailbox                 => SessionError.NotAddressedToMe
      case SdkError.DecryptionFailed             => SessionError.DecryptionFailed
      case SdkError.UnsupportedSdkType           => SessionError.UnsupportedSdkType
      case SdkError.MalformedEnvelope(r)         => SessionError.MalformedEnvelope(r)
      case SdkError.AddRequestVerificationFailed => SessionError.SdkError("add-request verification failed")
      case SdkError.BadDirectoryProof            => SessionError.SdkError("bad directory proof")
      case SdkError.InternalError(r)             => SessionError.SdkError(r)

    // Friendship is imported to keep the conceptual link explicit even
    // though we don't call it directly in this MVP — the AddRequest
    // surfacing relies on the SDK delivering Friendship.AddRequestContent.
    private val _ = Friendship.AlgorithmID.AddRequest_v1
