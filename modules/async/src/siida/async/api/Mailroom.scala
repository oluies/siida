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

package siida.async.api

import siida.mixnet.api.MixChain
import siida.observability.api.Telemetry

/** Dead-drop / mailroom for offline recipients (spec 009).
 *
 *  The mixnet's last hop produces `MailboxEnvelope`s addressed to
 *  per-recipient mailbox ids. Online recipients pick them up
 *  immediately; offline recipients need somewhere to hold them
 *  until they reconnect. This is that "somewhere."
 *
 *  Two MVP implementations:
 *  - `Mailroom.inMemory(ttlMs)` — a HashMap with lazy expiry.
 *  - `Mailroom.persistent(path, ttlMs)` — file-backed snapshot.
 *
 *  Future specs may wire NATS JetStream / dtn7-rs adapters.
 */
trait Mailroom:

  /** Deposit an envelope at logical time `nowMs`. Returns `false`
   *  iff the envelope was dropped on input (cover-traffic mailbox,
   *  broadcast mailbox, or already expired by TTL).
   */
  def deposit(env: MixChain.MailboxEnvelope, nowMs: Long): Boolean

  /** Retrieve all pending envelopes for `mailboxId` at logical time
   *  `nowMs`, in deposit order. The returned envelopes are removed
   *  from the mailroom. Expired envelopes are dropped silently
   *  (FR-003).
   */
  def retrieve(mailboxId: Long, nowMs: Long): Seq[MixChain.MailboxEnvelope]

  /** Current count of pending envelopes across all mailboxes.
   *  Expired envelopes may still be counted; call `retrieve(...)`
   *  on each mailbox to trigger expiry sweep.
   */
  def size: Int


object Mailroom:

  def inMemory(ttlMs: Long, telemetry: Telemetry = Telemetry.noop): Mailroom =
    new InMemoryMailroom(ttlMs, telemetry)

  def persistent(
    path:      java.nio.file.Path,
    ttlMs:     Long,
    telemetry: Telemetry = Telemetry.noop,
  ): Either[String, Mailroom] =
    PersistentMailroom.openOrCreate(path, ttlMs, telemetry)

  private[api] final case class Slot(env: MixChain.MailboxEnvelope, depositMs: Long)

  private final class InMemoryMailroom(ttlMs: Long, telemetry: Telemetry) extends Mailroom:

    private val byMailbox = scala.collection.mutable.HashMap.empty[Long, scala.collection.mutable.ArrayBuffer[Slot]]
    private var _size = 0

    def deposit(env: MixChain.MailboxEnvelope, nowMs: Long): Boolean =
      val id = MixChain.envelopeMailboxId(env)
      if id == MixChain.CoverMailboxId || id == MixChain.BroadcastMailboxId then
        telemetry.incrementCounter("mailroom.deposit.rejected", 1L)
        false
      else
        val slot = Slot(env, nowMs)
        byMailbox.getOrElseUpdate(id, scala.collection.mutable.ArrayBuffer.empty[Slot]) += slot
        _size += 1
        telemetry.incrementCounter("mailroom.deposit.accepted", 1L)
        telemetry.recordGauge("mailroom.backlog", _size.toDouble)
        true

    def retrieve(mailboxId: Long, nowMs: Long): Seq[MixChain.MailboxEnvelope] =
      val out = byMailbox.remove(mailboxId) match
        case None => Vector.empty[MixChain.MailboxEnvelope]
        case Some(buf) =>
          val expiry = nowMs - ttlMs
          val live = buf.filter(_.depositMs >= expiry)
          _size -= buf.length
          live.iterator.map(_.env).toVector
      telemetry.recordHistogram("mailroom.retrieve.envelopes_returned", out.length.toDouble)
      telemetry.recordGauge("mailroom.backlog", _size.toDouble)
      out

    def size: Int = _size
