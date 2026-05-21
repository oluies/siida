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

package siida.core

import java.io.{BufferedReader, PrintWriter, StringReader, StringWriter}
import java.security.SecureRandom
import munit.FunSuite
import siida.core.api.ChatSession
import siida.core.tui.TerminalUi
import siida.crypto.api.HybridOnion
import siida.pkg.api.FriendStore
import siida.sdk.api.{PeerCatalog, SiidaClient}

final class TerminalUiSuite extends FunSuite:

  private def fixedRng(label: String): SecureRandom =
    val rng = SecureRandom.getInstance("SHA1PRNG")
    rng.setSeed(label.getBytes("UTF-8"))
    rng

  private def mkSession(label: String): ChatSession =
    val mixPks = (0 until 2).map(i => HybridOnion.generateBundle(fixedRng(s"$label-mix-$i"))._2).toVector
    val (sk, pk) = HybridOnion.generateBundle(fixedRng(s"$label-me"))
    val (_, bobPk) = HybridOnion.generateBundle(fixedRng(s"$label-bob"))
    val catalog = PeerCatalog.inMemoryVerified(Map(
      IArray.unsafeFromArray("bob".getBytes("UTF-8")) -> PeerCatalog.Peer(bobPk, 2L),
    ))
    val sdk = SiidaClient.create("alice".getBytes("UTF-8"), sk, pk, 1L, mixPks, catalog)
    val fs = FriendStore.inMemory()
    fs.add("bob".getBytes("UTF-8"), bobPk)
    ChatSession.create("alice", sdk, fs)

  // ── Parse ─────────────────────────────────────────────────────

  test("SC-001: /msg bob hi there parses to Msg(bob, hi there)") {
    assertEquals(TerminalUi.parseCommand("/msg bob hi there"),
      Right(TerminalUi.Command.Msg("bob", "hi there")))
  }

  test("/help parses") {
    assertEquals(TerminalUi.parseCommand("/help"), Right(TerminalUi.Command.Help))
  }

  test("/friends parses") {
    assertEquals(TerminalUi.parseCommand("/friends"), Right(TerminalUi.Command.Friends))
  }

  test("/history parses") {
    assertEquals(TerminalUi.parseCommand("/history"), Right(TerminalUi.Command.History))
  }

  test("/quit parses") {
    assertEquals(TerminalUi.parseCommand("/quit"), Right(TerminalUi.Command.Quit))
  }

  test("/msg with no args → MalformedCommand") {
    val res = TerminalUi.parseCommand("/msg")
    res match
      case Left(TerminalUi.ParseError.MalformedCommand(_)) => ()
      case other => fail(s"expected MalformedCommand, got $other")
  }

  test("/msg with alias only → MalformedCommand") {
    val res = TerminalUi.parseCommand("/msg bob")
    res match
      case Left(TerminalUi.ParseError.MalformedCommand(_)) => ()
      case other => fail(s"expected MalformedCommand, got $other")
  }

  test("unknown /command → UnknownCommand") {
    val res = TerminalUi.parseCommand("/yodel")
    res match
      case Left(TerminalUi.ParseError.UnknownCommand("/yodel")) => ()
      case other => fail(s"expected UnknownCommand, got $other")
  }

  test("plain text without leading / → NotACommand") {
    assertEquals(TerminalUi.parseCommand("hello"),
      Left(TerminalUi.ParseError.NotACommand))
  }

  // ── Apply ─────────────────────────────────────────────────────

  test("SC-002: /friends prints both aliases") {
    val s = mkSession("fr")
    val out = TerminalUi.applyCommand(TerminalUi.Command.Friends, s, fixedRng("fr-r"))
    assert(out.contains("bob"), s"expected 'bob' in output, got: $out")
  }

  test("SC-003: /msg ghost → unknown-friend error") {
    val s = mkSession("uk")
    val out = TerminalUi.applyCommand(TerminalUi.Command.Msg("ghost", "hi"), s, fixedRng("uk-r"))
    assert(out.contains("unknown friend"), s"expected 'unknown friend' in output, got: $out")
  }

  test("/msg bob hi → records outbound + returns confirmation line") {
    val s = mkSession("ok")
    val out = TerminalUi.applyCommand(TerminalUi.Command.Msg("bob", "hi"), s, fixedRng("ok-r"))
    assertEquals(out, "-> bob: hi")
    assertEquals(s.history.length, 1)
  }

  test("/history shows recorded lines") {
    val s = mkSession("hist")
    val _ = TerminalUi.applyCommand(TerminalUi.Command.Msg("bob", "one"), s, fixedRng("hist-1"))
    val _ = TerminalUi.applyCommand(TerminalUi.Command.Msg("bob", "two"), s, fixedRng("hist-2"))
    val out = TerminalUi.applyCommand(TerminalUi.Command.History, s, fixedRng("hist-r"))
    assert(out.contains("one") && out.contains("two"), s"got: $out")
  }

  test("/history on empty session returns '(empty history)'") {
    val s = mkSession("emp")
    val out = TerminalUi.applyCommand(TerminalUi.Command.History, s, fixedRng("emp-r"))
    assertEquals(out, "(empty history)")
  }

  // ── Render ────────────────────────────────────────────────────

  test("SC-004: renderInbound(Chat(Inbound)) → \"<- alias: text\"") {
    val ev = ChatSession.InboundEvent.Chat(ChatSession.ChatLine.Inbound("alice", "hi"))
    assertEquals(TerminalUi.renderInbound(ev), "<- alice: hi")
  }

  test("renderInbound(AddRequest) → hex sender prefix") {
    val ev = ChatSession.InboundEvent.AddRequest(Array[Byte](0xab.toByte, 0xcd.toByte))
    val rendered = TerminalUi.renderInbound(ev)
    assert(rendered.startsWith("!! add-request from "), s"got: $rendered")
    assert(rendered.contains("abcd"), s"missing hex: $rendered")
  }

  // ── REPL smoke (just verify it terminates and prints output) ──

  test("repl: /quit terminates the loop") {
    val s = mkSession("repl")
    val in = new BufferedReader(new StringReader("/quit\n"))
    val sw = new StringWriter()
    val out = new PrintWriter(sw)
    TerminalUi.repl(s, fixedRng("repl-r"), in, out)
    val printed = sw.toString
    assert(printed.contains("[bye]"), s"expected bye in output, got: $printed")
  }

  test("repl: EOF terminates without [bye]") {
    val s = mkSession("eof")
    val in = new BufferedReader(new StringReader(""))
    val sw = new StringWriter()
    val out = new PrintWriter(sw)
    TerminalUi.repl(s, fixedRng("eof-r"), in, out)
    val printed = sw.toString
    assert(!printed.contains("[bye]"), s"EOF should not say bye, got: $printed")
  }

  test("repl: /msg goes through, /quit ends") {
    val s = mkSession("seq")
    val in = new BufferedReader(new StringReader("/msg bob hello\n/quit\n"))
    val sw = new StringWriter()
    val out = new PrintWriter(sw)
    TerminalUi.repl(s, fixedRng("seq-r"), in, out)
    val printed = sw.toString
    assert(printed.contains("-> bob: hello"), s"got: $printed")
    assert(printed.contains("[bye]"), s"got: $printed")
    assertEquals(s.history.length, 1)
  }
