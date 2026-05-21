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

package siida.core.tui

import java.io.{BufferedReader, PrintWriter}
import java.security.SecureRandom
import siida.core.api.ChatSession

/** Terminal UI for ChatSession (spec 026 MVP).
 *
 *  Three pure surfaces:
 *  - parseCommand(line) → Either[ParseError, Command]
 *  - applyCommand(cmd, session, rng) → String (rendered)
 *  - renderInbound(event) → String
 *
 *  Plus a thin REPL (`repl`) that glues stdin/stdout — the REPL
 *  loop is intentionally not unit-tested; the commands inside
 *  it are.
 */
object TerminalUi:

  enum Command derives CanEqual:
    case Help
    case Friends
    case Msg(alias: String, text: String)
    case History
    case Quit

  enum ParseError derives CanEqual:
    case UnknownCommand(input: String)
    case MalformedCommand(usage: String)
    case NotACommand // input did not start with `/`

  // ── Parse ─────────────────────────────────────────────────────

  def parseCommand(line: String): Either[ParseError, Command] =
    val trimmed = line.trim
    if !trimmed.startsWith("/") then Left(ParseError.NotACommand)
    else
      val parts = trimmed.split(' ').toList
      parts match
        case "/help"    :: Nil           => Right(Command.Help)
        case "/friends" :: Nil           => Right(Command.Friends)
        case "/history" :: Nil           => Right(Command.History)
        case "/quit"    :: Nil           => Right(Command.Quit)
        case "/msg"     :: Nil           =>
          Left(ParseError.MalformedCommand("/msg <alias> <text>"))
        case "/msg"     :: alias :: rest =>
          if rest.isEmpty then Left(ParseError.MalformedCommand("/msg <alias> <text>"))
          else Right(Command.Msg(alias, rest.mkString(" ")))
        case cmd :: _    => Left(ParseError.UnknownCommand(cmd))
        case Nil         => Left(ParseError.MalformedCommand("(empty)"))

  // ── Apply ─────────────────────────────────────────────────────

  /** Returns a human-readable rendered string for the loop to print.
   *  Quit returns a sentinel "[bye]" — the caller is responsible
   *  for actually breaking the loop.
   */
  def applyCommand(
    cmd:     Command,
    session: ChatSession,
    rng:     SecureRandom,
  ): String =
    cmd match
      case Command.Help    => helpText
      case Command.Friends =>
        val list = session.friends
        if list.isEmpty then "(no friends)"
        else "friends:\n  " + list.mkString("\n  ")
      case Command.Msg(alias, text) =>
        session.sendChat(alias, text, rng) match
          case Right(_)  => s"-> $alias: $text"
          case Left(ChatSession.SessionError.UnknownFriend(a)) =>
            s"unknown friend: $a (try /friends)"
          case Left(other) => s"send failed: $other"
      case Command.History =>
        if session.history.isEmpty then "(empty history)"
        else session.history.iterator.map(renderLine).mkString("\n")
      case Command.Quit => "[bye]"

  // ── Render helpers ────────────────────────────────────────────

  def renderLine(line: ChatSession.ChatLine): String = line match
    case ChatSession.ChatLine.Outbound(to, text)   => s"-> $to: $text"
    case ChatSession.ChatLine.Inbound(from, text)  => s"<- $from: $text"

  def renderInbound(event: ChatSession.InboundEvent): String = event match
    case ChatSession.InboundEvent.Chat(line) =>
      renderLine(line)
    case ChatSession.InboundEvent.AddRequest(senderId) =>
      s"!! add-request from ${hex(senderId)}"

  def renderParseError(err: ParseError): String = err match
    case ParseError.UnknownCommand(cmd)   => s"huh? unknown command: $cmd (try /help)"
    case ParseError.MalformedCommand(use) => s"usage: $use"
    case ParseError.NotACommand           => "huh? try /help"

  private def hex(bytes: Array[Byte]): String =
    bytes.iterator.map(b => f"${b & 0xFF}%02x").mkString

  private val helpText: String =
    """commands:
      |  /help              this message
      |  /friends           list known aliases
      |  /msg <alias> <text>  send a chat
      |  /history           print chat log
      |  /quit              exit""".stripMargin

  // ── REPL glue (not unit-tested) ───────────────────────────────

  /** stdin/stdout loop. Exits cleanly on `/quit` or EOF. */
  def repl(
    session: ChatSession,
    rng:     SecureRandom,
    in:      BufferedReader,
    out:     PrintWriter,
  ): Unit =
    out.println(s"siida tui — session ${session.myAlias}. /help for commands.")
    out.flush()
    var running = true
    while running do
      out.print("> "); out.flush()
      val line = in.readLine()
      if line == null then running = false
      else
        parseCommand(line) match
          case Right(Command.Quit) =>
            out.println("[bye]"); out.flush()
            running = false
          case Right(cmd) =>
            out.println(applyCommand(cmd, session, rng)); out.flush()
          case Left(ParseError.NotACommand) if line.trim.isEmpty =>
            () // skip blank lines silently
          case Left(err) =>
            out.println(renderParseError(err)); out.flush()
