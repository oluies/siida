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

package siida.agent.api

import java.security.SecureRandom
import siida.crypto.api.HybridOnion
import siida.sdk.api.{SdkError, SiidaClient}

/** Agent messaging convention layer (spec 008 MVP).
 *
 *  Wraps a `SiidaClient` and adds:
 *  - `sendRequest(peer, payload, rng)` → with a freshly-generated UUID
 *  - `sendResponse(peer, requestId, payload, rng)` → echoes the UUID
 *  - `sendNotification(peer, payload, rng)` → zero UUID
 *  - `deliverAgent(envelope)` → typed `AgentIncoming`
 *
 *  Backward compat: a chat payload without the SIAG magic prefix is
 *  surfaced as `AgentIncoming.RawChat` rather than failing.
 */
trait AgentClient:

  def sendRequest(
    recipientIdentity: Array[Byte],
    payload:           Array[Byte],
    rng:               SecureRandom,
  ): Either[SdkError, (HybridOnion.OnionLayer, Array[Byte] /* requestId */)]

  def sendResponse(
    recipientIdentity: Array[Byte],
    requestId:         Array[Byte],
    payload:           Array[Byte],
    rng:               SecureRandom,
  ): Either[SdkError, HybridOnion.OnionLayer]

  def sendNotification(
    recipientIdentity: Array[Byte],
    payload:           Array[Byte],
    rng:               SecureRandom,
  ): Either[SdkError, HybridOnion.OnionLayer]

  def deliverAgent(
    envelopeBytes: Array[Byte],
  ): Either[SdkError, AgentClient.AgentIncoming]


object AgentClient:

  enum AgentIncoming derives CanEqual:
    case Request(requestId: Array[Byte], content: Array[Byte])
    case Response(requestId: Array[Byte], content: Array[Byte])
    case Notification(content: Array[Byte])
    case RawChat(payload: Array[Byte])

  def from(siida: SiidaClient): AgentClient = new SiidaAgentClient(siida)

  private final class SiidaAgentClient(siida: SiidaClient) extends AgentClient:

    def sendRequest(
      recipientIdentity: Array[Byte],
      payload:           Array[Byte],
      rng:               SecureRandom,
    ): Either[SdkError, (HybridOnion.OnionLayer, Array[Byte])] =
      val rid = newRequestId(rng)
      val env = AgentEnvelope.encode(AgentEnvelope.Kind.Request, rid, payload)
      siida.sendChatMessage(recipientIdentity, env, rng).map((_, rid))

    def sendResponse(
      recipientIdentity: Array[Byte],
      requestId:         Array[Byte],
      payload:           Array[Byte],
      rng:               SecureRandom,
    ): Either[SdkError, HybridOnion.OnionLayer] =
      val env = AgentEnvelope.encode(AgentEnvelope.Kind.Response, requestId, payload)
      siida.sendChatMessage(recipientIdentity, env, rng)

    def sendNotification(
      recipientIdentity: Array[Byte],
      payload:           Array[Byte],
      rng:               SecureRandom,
    ): Either[SdkError, HybridOnion.OnionLayer] =
      val env = AgentEnvelope.encode(AgentEnvelope.Kind.Notification, AgentEnvelope.ZeroRequestId, payload)
      siida.sendChatMessage(recipientIdentity, env, rng)

    def deliverAgent(
      envelopeBytes: Array[Byte],
    ): Either[SdkError, AgentIncoming] =
      siida.deliver(envelopeBytes).map {
        case SiidaClient.IncomingMessage.ChatMessage(payload) =>
          decodeAgent(payload)
        case SiidaClient.IncomingMessage.AuthenticatedChat(_, payload) =>
          // Spec 023: the SDK already gives us the sender identity,
          // but the agent layer's typed surface doesn't currently
          // expose a sender field. Decode the agent envelope from
          // the payload bytes; if not SIAG, surface as RawChat.
          // Agents that need the sender go through SiidaClient.deliver
          // directly.
          decodeAgent(payload)
        case SiidaClient.IncomingMessage.AddRequest(_) =>
          // Add-requests are surfaced at the SDK level, not the agent
          // convention; we still surface them by wrapping in a
          // distinct "non-agent" path. The agent caller can branch
          // on the SDK delivery instead if it cares about add-requests.
          AgentIncoming.RawChat(Array.emptyByteArray)
      }

    private def decodeAgent(payload: Array[Byte]): AgentIncoming =
      AgentEnvelope.decode(payload) match
        case None => AgentIncoming.RawChat(payload)
        case Some(d) =>
          d.kind match
            case AgentEnvelope.Kind.Request      => AgentIncoming.Request(d.requestId, d.content)
            case AgentEnvelope.Kind.Response     => AgentIncoming.Response(d.requestId, d.content)
            case AgentEnvelope.Kind.Notification => AgentIncoming.Notification(d.content)
            case _                               => AgentIncoming.RawChat(payload)

    private def newRequestId(rng: SecureRandom): Array[Byte] =
      val out = new Array[Byte](AgentEnvelope.RequestIdBytes)
      rng.nextBytes(out)
      out
