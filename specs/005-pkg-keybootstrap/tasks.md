---
description: "Task list for 005-pkg-keybootstrap (MVP)"
---

# Tasks: PKG Key-Bootstrap (MVP)

**Input**: Design documents from `/specs/005-pkg-keybootstrap/`

**Prerequisites**: spec.md, plan.md, research.md, contracts/{scala-api.md, wire-format.md}. Specs 012, 013, 015 (and 014's
MultiSignedEntry primitive folded into 015's PR) and 004 are on main.

**Tests**: Issuance + duplicate rejection, mailbox-id allocation
with reserved-id skip, snapshot composition with 015,
configuration-validation errors.

**Organization**: Three user stories (US1 issuance, US2 duplicate
rejection, US3 snapshot composition).

---

## Phase 1: Setup

- [X] T001 Add `modules.pkg.moduleDeps = Seq(modules.crypto,
  modules.mixnet)` to `build.mill`. Mixnet dep is needed for
  `MixChain.CoverMailboxId` / `BroadcastMailboxId` constants
  during reserved-id skipping. _(done)_
- [X] T002 Remove `modules/pkg/src/Placeholder.scala` and
  `modules/pkg/test/src/PlaceholderSuite.scala`. _(done)_

---

## Phase 2: Foundational

- [X] T003 [P] Write `modules/pkg/src/siida/pkg/api/Errors.scala`:
  `enum PkgError derives CanEqual` with `EmptyRoster`,
  `InvalidThreshold`, `RosterKeyMismatch`,
  `IdentityAlreadyExists`, `MailboxIdExhausted`. _(done)_
- [X] T004 [P] Write
  `modules/pkg/src/siida/pkg/api/IssuedIdentity.scala`: case
  class containing `secretBundle`, `mailboxId`, `publicBundle`,
  `proof`. _(done)_
- [X] T005 [P] Write
  `modules/pkg/src/siida/pkg/api/DirectoryEntryWire.scala`:
  encode + decode for the FR-006 wire format
  (`2 + identity_len + 8 + 1216` bytes). _(done)_

---

## Phase 3: User Story 1 — Issue identity, populate directory (Priority: P1)

- [X] T006 [US1] Write `modules/pkg/src/siida/pkg/api/Pkg.scala`:
  `Pkg` trait + `InMemoryPkg` impl. `Pkg.create` validates config
  (non-empty roster, threshold ≤ roster size, key-count parity).
  `issueIdentity` generates fresh HybridSecretBundle, allocates
  mailbox-id (skipping reserved 0 / -1), signs the binding via
  `MultiSignedEntry.assemble` with signers `[0, threshold)`,
  stores public bundle + mailbox-id + proof; returns
  `IssuedIdentity`. `directorySnapshot` exposes the state as
  `IdentityEncryption.Directory`. _(done)_
- [X] T007 [US1] Write `modules/pkg/test/src/PkgSuite.scala`:
  5 tests covering issuance returns sensible values, sequential
  mailbox-id allocation with reserved-id skip, fixed-seed
  determinism, and the SC-006 "PKG does not retain secrets" API-
  surface check. _(done; 5/5 green)_

---

## Phase 4: User Story 2 — Duplicate identity rejected (Priority: P1)

- [X] T008 [US2] Duplicate-rejection test is included in
  `PkgSuite` ("duplicate identity → IdentityAlreadyExists; state
  unchanged"). The test verifies that after the rejected
  duplicate, bob can still be issued and gets a distinct
  mailbox-id. _(done)_

---

## Phase 5: User Story 3 — Snapshot end-to-end (Priority: P1)

- [X] T009 [US3] Write `modules/pkg/test/src/DirectorySnapshotSuite.scala`:
  4 tests covering 3-identity end-to-end encryption (issue → send
  → decrypt for alice, bob, carol), IdentityNotFound on miss,
  snapshot-time semantics (snapshot taken before bob's issuance
  doesn't include bob), and DirectoryEntryWire round-trip. _(done)_

---

## Phase 6: Configuration validation

- [X] T010 Write `modules/pkg/test/src/PkgErrorsSuite.scala`:
  4 tests covering empty roster, threshold > roster size,
  threshold = 0, and mismatched key counts. _(done; 4/4 green)_

---

## Phase N: Polish & Cross-Cutting

- [X] T011 Run `make check`; expect green. _(EXIT=0)_
- [X] T012 Update `README.md` roadmap: 005 entry's "(sketched)"
  tag (if any) → MVP scope statement. _(done in same PR)_
- [X] T013 Confirm test counts: PKG module went from 1
  (placeholder) to 13 (5 + 4 + 4 across three suites). _(confirmed)_

---

## Notes

- **MVP only**: friend-discovery (Alpenhorn add-request flow),
  persistent storage, network transport, sybil resistance, and
  roster rotation are deferred to follow-up specs. See spec.md
  out-of-scope subsection.
- **PKG state is mutable** (the directory accumulates entries).
  Trade-off documented in plan.md complexity tracking.
- **Threshold signer selection** is signers `[0, threshold)` —
  the first M of N in roster order. Production policy-driven
  selection is a follow-up.
- **PKG doesn't retain secret bundles** (SC-006): verifiable by
  inspection of `Pkg.scala` — no field of type
  `HybridSecretBundle` lives on `InMemoryPkg`; the secret is
  returned and forgotten. PkgSuite includes a smoke test by API
  surface absence.
- **Mailbox-id space**: 64-bit signed Long; reserved values 0
  (cover) and -1 (broadcast). Allocator skips both.
- The DirectoryEntryWire payload format (`2 + identity_len + 8
  + 1216`) is fixed at MVP. A future spec adding expiry /
  issued-at fields would bump `MultiSignedEntry.FormatVersion`
  from 0x01 to 0x02.
