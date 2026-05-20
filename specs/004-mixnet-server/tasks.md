---
description: "Task list for 004-mixnet-server (MVP)"
---

# Tasks: Mixnet Server (MVP)

**Input**: Design documents from `/specs/004-mixnet-server/`

**Prerequisites**: spec.md, plan.md, research.md, contracts/{scala-api.md, wire-format.md}. Spec 012 (HybridOnion) is on main.

**Tests**: Round-trip through chain, mixer integrity, cover-traffic
indistinguishability, deterministic shuffles, performance.

**Organization**: Three user stories — US1 end-to-end round, US2
mixer integrity, US3 cover traffic — plus polish.

---

## Phase 1: Setup

- [X] T001 Add `modules.mixnet` dependency on `modules.crypto`:
  `override def moduleDeps = Seq(modules.crypto)` (plus the same
  for `test.moduleDeps`). _(done; build.mill line ~183)_
- [X] T002 Delete `modules/mixnet/src/Placeholder.scala` and
  `modules/mixnet/test/src/PlaceholderSuite.scala`. The mixnet
  module now has real content. _(done)_

---

## Phase 2: Foundational

- [X] T003 [P] Write `modules/mixnet/src/siida/mixnet/api/Errors.scala`:
  `enum MixnetError derives CanEqual` with `InvalidLength`,
  `MalformedEnvelope(reason)`, `ChainLengthMismatch(have, want)`,
  `ShuffleSeedSize(have, want)`. _(done)_
- [X] T004 [P] Write `modules/mixnet/src/siida/mixnet/internal/Shuffle.scala`:
  deterministic Fisher-Yates from a 32-byte SHA1PRNG seed. Index-
  based to avoid ClassTag requirements. AGPL header. _(done)_

---

## Phase 3: User Story 1 — End-to-end round (Priority: P1)

- [X] T005 [US1] Write `modules/mixnet/src/siida/mixnet/api/MixChain.scala`:
  - opaque type `MailboxEnvelope`
  - `envelope(id, payload)` / `envelopeMailboxId` / `envelopePayload`
    accessors
  - `serialiseEnvelope` / `deserialiseEnvelope`
  - `layeredSubmission(chain, env, rng)` — fold from inner-most
    mixer outward, returning the outermost `OnionLayer`
  - `coverSubmission(chain, payloadLen, rng)` — targets
    `CoverMailboxId = 0` with random payload
  - Reserved IDs `CoverMailboxId` (0), `BroadcastMailboxId` (-1)
  _(done)_
- [X] T006 [US1] Write `modules/mixnet/src/siida/mixnet/api/Mixer.scala`:
  `peel(secret, layer): Option[Array[Byte]]` — silent-drop
  semantics on failure (FR-004). _(done)_
- [X] T007 [US1] Write `modules/mixnet/src/siida/mixnet/api/Coordinator.scala`:
  `runRound(submissions, chainSecrets, shuffleSeeds)` returns
  `RoundResult(deliveries, metrics)`. Pure deterministic function
  modulo crypto (FR-003). Per-mixer drop counts in metrics. _(done)_
- [X] T008 [US1] Write `modules/mixnet/test/src/MixChainSuite.scala`
  — 5 tests covering envelope round-trip, reserved IDs, chain peel-
  back, cover indistinguishability by wire length, deserialise
  length rejection. _(done; all green)_
- [X] T009 [US1] Write `modules/mixnet/test/src/RoundSuite.scala`
  — 5 tests covering 8-client/3-mixer happy path (SC-001),
  determinism (SC-002), tampered submission drop (SC-003), empty
  round, performance under 500 ms (SC-004). _(done; all green)_

---

## Phase 4: User Story 2 — Mixer integrity (Priority: P1)

- [X] T010 [US2] Write `modules/mixnet/test/src/MixerSuite.scala`
  — 3 tests: HNDL-style integrity (mixer 1 cannot peel mixer 2's
  layer), malformed layer drop, matching-secret round-trip. _(done)_

---

## Phase 5: User Story 3 — Cover traffic (Priority: P2)

- [X] T011 [US3] Write `modules/mixnet/test/src/CoverTrafficSuite.scala`
  — 2 tests: mixed 4 real + 4 cover batch all delivered with covers
  going to `CoverMailboxId`, and same-payload-length real and cover
  submissions have identical wire bytes (FR-007). _(done; both green)_

---

## Phase N: Polish & Cross-Cutting

- [X] T012 Run `make check` end-to-end (headers + compile + test
  + ci-parity); expect green. _(EXIT=0; 2026-05-20 on darwin-arm64)_
- [X] T013 [P] Update `README.md` roadmap: 004 entry's
  "(sketched)" tag is no longer accurate; it now ships an MVP.
  Insert the MVP scope-callout. _(done in the same PR)_
- [X] T014 [P] Confirm test counts: mixnet went from 1
  (placeholder) to 15 (5 MixChain + 3 Mixer + 5 Round + 2 Cover).
  Total project test count rose by 14. _(confirmed)_

---

## Dependencies

- Phase 1 setup blocks all subsequent work
- Phase 2 foundational utilities block US1
- US1 + US2 + US3 can run in parallel after Phase 2
- Polish runs after all stories

## Notes

- **MVP only**: spec.md "out-of-scope" subsection enumerates what
  this PR does NOT do. Network transport, persistence, recovery,
  observability, roster rotation are deferred to follow-up specs.
- **Pekko Streams not used in this MVP**: the in-process pipeline
  uses plain Vector operations. The plan mentioned Pekko Streams
  as a future-proofing path; for the MVP, deterministic
  in-process processing is enough and matches FR-003 better than
  a Pekko-Streams materialisation would.
- **Shuffle is plain Fisher-Yates** seeded from a 32-byte
  CSPRNG draw per round per mixer. Not a verifiable shuffle (per
  research R2). The seed is publishable post-round for audit.
- **No new external dependencies** introduced by 004. Crypto
  module (with BC 1.84) is the only inter-module dep.
- The 002 BLSSuite (BLS-over-BN254) is still in service via
  `@nowarn("cat=deprecation")` from spec 013; nothing changes
  here.
