# Feature Specification: Terminal UI for ChatSession

**Feature Branch**: `026-tui-chat`

**Created**: 2026-05-21

**Status**: Draft (MVP)

## Why this spec exists

Spec 010 ships the headless `ChatSession` model. The README has
always called out a terminal UI as the first real user surface
(replacing Vuvuzela's `gocui`). This spec ships that TUI as a
small command-driven REPL: pure command parser + renderer +
thin stdin/stdout loop.

The TUI's command parser and renderer are pure functions so they
can be unit-tested. The actual `main` loop is one screenful of
glue that the integration test skips.

## User Scenarios

### US1 — Parse and execute commands (P1)

```
/help                  → list commands
/friends               → list aliases in the FriendStore
/msg bob hello there   → send to bob via ChatSession
/history               → print the chat log
/quit                  → exit the loop
```

`parseCommand("/msg bob hi")` returns
`Command.Msg("bob", "hi")`; `applyCommand(Msg(...), rng, session)`
calls `session.sendChat(...)` and returns a string the loop prints.

### US2 — Render chat history (P2)

`renderHistory(session.history)` formats each line as either
`"-> {alias}: {text}"` for outbound or `"<- {alias}: {text}"` for
inbound.

### US3 — Render inbound deliveries (P2)

`renderInbound(event)` formats an `InboundEvent` — for chats it's
the same as `renderHistory`; for `AddRequest` it renders
`"!! add-request from <hex sender>"`.

### Edge cases

- Unknown command (no leading `/`) is treated as a typing accident
  and ignored with a "huh? try /help" hint.
- `/msg` with too few args: `parseCommand("/msg")` returns
  `ParseError.MalformedCommand("/msg <alias> <text>")`.
- `applyCommand(Msg("unknown", ...))` surfaces the
  `UnknownFriend` error as a human-readable line, not a
  stack trace.

## Functional Requirements

- **FR-001**: `TerminalUi.parseCommand(line: String)` MUST return
  `Either[ParseError, Command]` and MUST be a pure function.
- **FR-002**: `TerminalUi.applyCommand(cmd, session, rng)` MUST
  delegate side-effects to `ChatSession` only and return a
  rendered string (multi-line for `/history` and `/friends`).
- **FR-003**: `TerminalUi.renderInbound(event)` MUST format any
  `ChatSession.InboundEvent` as a human-readable line.
- **FR-004**: A `TerminalUi.repl(session, rng, in, out)` MUST
  exist as the actual stdin/stdout glue. Its loop is NOT covered
  by unit tests; the commands inside it are.

## Success Criteria

- **SC-001**: `parseCommand("/msg bob hi there")` returns
  `Right(Msg("bob", "hi there"))`.
- **SC-002**: `applyCommand(Friends, session, rng)` over a session
  with friends `[alice, bob]` returns a string containing both.
- **SC-003**: `applyCommand(Msg("ghost", "hi"), session, rng)`
  returns a string mentioning "unknown friend: ghost".
- **SC-004**: `renderInbound(Chat(Inbound("alice", "hi")))` matches
  `"<- alice: hi"`.

## Out of scope

- Pretty-printing / colours / cursor management.
- History up/down (no readline integration).
- Mouse / paste / multi-line input.
- Persistent terminal config.

## Dependencies

- 010 chat-client (`ChatSession`).
- Nothing new — the TUI lives inside the existing `modules.core`.
