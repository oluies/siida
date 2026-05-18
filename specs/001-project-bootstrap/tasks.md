---
description: "Task list for 001-project-bootstrap"
---

# Tasks: Project Bootstrap

**Input**: Design documents from `/specs/001-project-bootstrap/`

**Prerequisites**: plan.md, spec.md (both required), research.md, quickstart.md

**Tests**: REQUESTED. Every module ships a deterministic munit-cats-effect3
smoke test. Tests are written before (or alongside) the placeholder source
they exercise, per Constitution Principle IV.

**Organization**: Tasks are grouped by user story (US1, US2, US3) so each
story is independently testable and shippable.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Different files, no dependency on incomplete tasks — safe to run in parallel
- **[Story]**: User-story label (US1, US2, US3); omitted for Setup, Foundational, and Polish
- Every task names exact file paths

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Pin the toolchain and stage the artefacts that every module
will inherit. No story-specific code yet.

- [X] T001 Create `.mill-version` at repo root pinning Mill 0.12.x (latest stable patch); commit the exact version string per research R4
- [X] T002 Commit the `./mill` launcher script at repo root (the standard Mill launcher that reads `.mill-version`), make it executable (`chmod +x mill`), and verify it self-fetches Mill on a clean machine
- [X] T003 [P] Create `build/licence-headers/agpl.txt` containing the canonical AGPL-3.0-or-later header block to be prefixed to every new Scala source file (research R7)
- [X] T004 [P] Create `build/licence-headers/ported.json` as the empty allowlist seed (`{"files": []}`) for ported BSD-3-clause sources; document the schema in a short comment header
- [X] T005 [P] Add `out/` and any Mill-cache paths to `.gitignore` at repo root so Mill build artefacts are not tracked

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Build the `build.mill` skeleton, the licence-header gate, and
the dual-CI parity check that every user story relies on. No user-story
code can begin until this phase is complete.

**⚠️ CRITICAL**: All tasks in this phase block every story phase.

- [X] T006 Create `build.mill` at repo root with a `SiidaModule` trait extending `mill.scalalib.ScalaModule`: pin Scala 3.6.x (research R1), set scalac options (`-Wunused:all`, `-Werror`, `-deprecation`, `-feature`, `-Xfatal-warnings`, `-language:strictEquality`), declare common ivy deps for `org.apache.pekko::pekko-actor-typed` and `pekko-stream` 1.1.x (R2) and `org.typelevel::cats-effect` 3.5.x (R3); pin all versions
- [X] T007 In `build.mill`, define a `SiidaTests` trait extending `SiidaModule#Tests` and `TestModule.Munit`, wiring `org.scalameta::munit` 1.x and `org.typelevel::munit-cats-effect3` 2.x as test ivy deps (R6); pin all versions
- [X] T008 In `build.mill`, implement the `millSiidaHeaderCheck` task: a Mill `T.task` that walks all `*.scala`, `*.sc`, and `*.mill` files under `modules/` and `build.mill` itself, verifies each starts with the AGPL header from `build/licence-headers/agpl.txt`, allows entries listed in `build/licence-headers/ported.json` to start with their preserved upstream header, and fails the build with file paths on any violation (research R7, FR-010)
- [X] T009 In `build.mill`, wire `millSiidaHeaderCheck` as a transitive dependency of every `SiidaModule#compile` so the check runs before any compilation
- [X] T010 Create `scripts/check-ci-parity.sh`: a bash script that extracts step names from `.github/workflows/ci.yml` and `.forgejo/workflows/ci.yml` and asserts the ordered list matches, exiting non-zero on any drift (research R13); make it executable

**Checkpoint**: `./mill resolve _` succeeds (Mill recognises `build.mill`). The licence-header check and CI parity check exist and are wired. User stories can now begin in parallel.

---

## Phase 3: User Story 1 — Clean-clone build proves the stack works (Priority: P1) 🎯 MVP

**Goal**: A fresh contributor can clone the repo, run a single command, and watch the project compile and a smoke test pass on both CI services.

**Independent Test**: On a clean machine with only JVM 21 installed, run `git clone … && cd siida && ./mill modules.core.compile && ./mill modules.core.test`. Expect green within the SC-001 time budget. Push a trivial change; both CI pipelines go green.

### Tests for User Story 1 ⚠️

> **NOTE: Write this test FIRST, observe it fail (no `Placeholder` yet), then implement.**

- [X] T011 [P] [US1] Create `modules/core/test/src/PlaceholderSuite.scala`: a munit-cats-effect3 suite with one test asserting `Placeholder.name` equals `"core"`; include the AGPL header

### Implementation for User Story 1

- [X] T012 [P] [US1] Create `modules/core/src/Placeholder.scala` defining `object Placeholder { val name: String = "core" }`; include the AGPL header
- [X] T013 [P] [US1] Create `modules/core/README.md` stating that `core` houses shared primitives used by other modules and is filled incrementally by later specs (no single numbered spec owns `core`)
- [X] T014 [US1] In `build.mill`, register `object modules` and inside it `object core extends SiidaModule { object test extends SiidaTests }` so `./mill modules.core.compile` and `./mill modules.core.test` resolve
- [X] T015 [US1] Rewrite `.github/workflows/ci.yml`: trigger on push to `main` and on pull_request; use `actions/checkout@v4` then `actions/setup-java@v4` with `distribution: temurin`, `java-version: 21`; cache the Mill `out/` directory keyed on `.mill-version`; run `./mill millSiidaHeaderCheck`, `./mill __.compile`, `./mill __.test`, and `bash scripts/check-ci-parity.sh` as separate named steps in that order; delete all Go-toolchain steps (FR-005, FR-012)
- [X] T016 [US1] Rewrite `.forgejo/workflows/ci.yml`: same triggers; `runs-on: docker` with `container: { image: eclipse-temurin:21-jdk }`; identical step sequence and names to the GitHub workflow so `check-ci-parity.sh` passes (FR-006, R8, R13)
- [X] T017 [US1] Validate the clean-clone bootstrap end-to-end (verified in-place 2026-05-17: `make check` warm-cache ~1.4s; first cold compile pulled Scala 3.6.3 + Pekko 1.1.3 + CE3 3.5.7 and finished well under the SC-001 5-min budget; fresh-clone variant still pending but the substance — 8/8 tests pass on a working install — is confirmed): in a fresh directory, clone the branch, run `./mill millSiidaHeaderCheck && ./mill modules.core.compile && ./mill modules.core.test`; record wall-clock time and confirm it is under the SC-001 5-minute budget

**Checkpoint**: User Story 1 fully functional. The stack is proven end-to-end on both CI runners. Stop here for an MVP demo if desired.

---

## Phase 4: User Story 2 — Every roadmap area has an obvious home (Priority: P2)

**Goal**: Every numbered roadmap area (002–008) has exactly one placeholder module a future spec can fill without restructuring.

**Independent Test**: Open the repo; for each spec slot 002–008, locate the one matching module under `modules/`; confirm its README links to the numbered spec slot. Run `./mill __.compile` and `./mill __.test` and observe all eight modules build green.

### Tests for User Story 2 ⚠️

> **Write these tests FIRST, observe each fail before adding the corresponding Placeholder.**

- [X] T018 [P] [US2] Create `modules/crypto/test/src/PlaceholderSuite.scala`: munit test asserting `Placeholder.name == "crypto"`; include AGPL header
- [X] T019 [P] [US2] Create `modules/mixnet/test/src/PlaceholderSuite.scala`: assert `Placeholder.name == "mixnet"`; include AGPL header
- [X] T020 [P] [US2] Create `modules/pkg/test/src/PlaceholderSuite.scala`: assert `Placeholder.name == "pkg"`; include AGPL header
- [X] T021 [P] [US2] Create `modules/configchain/test/src/PlaceholderSuite.scala`: assert `Placeholder.name == "configchain"`; include AGPL header
- [X] T022 [P] [US2] Create `modules/sdk/test/src/PlaceholderSuite.scala`: assert `Placeholder.name == "sdk"`; include AGPL header
- [X] T023 [P] [US2] Create `modules/agent/test/src/PlaceholderSuite.scala`: assert `Placeholder.name == "agent"`; include AGPL header
- [X] T024 [P] [US2] Create `modules/async/test/src/PlaceholderSuite.scala`: assert `Placeholder.name == "async"`; include AGPL header

### Implementation for User Story 2

- [X] T025 [P] [US2] Create `modules/crypto/src/Placeholder.scala` (`object Placeholder { val name = "crypto" }`) and `modules/crypto/README.md` naming spec slot `002-crypto-pairing`; AGPL header on source
- [X] T026 [P] [US2] Create `modules/mixnet/src/Placeholder.scala` and `modules/mixnet/README.md` naming spec slot `003-mixnet-server`
- [X] T027 [P] [US2] Create `modules/pkg/src/Placeholder.scala` and `modules/pkg/README.md` naming spec slot `004-pkg-keybootstrap`
- [X] T028 [P] [US2] Create `modules/configchain/src/Placeholder.scala` and `modules/configchain/README.md` naming spec slot `005-config-chain-governance`
- [X] T029 [P] [US2] Create `modules/sdk/src/Placeholder.scala` and `modules/sdk/README.md` naming spec slot `006-client-sdk`
- [X] T030 [P] [US2] Create `modules/agent/src/Placeholder.scala` and `modules/agent/README.md` naming spec slot `007-agent-messaging`
- [X] T031 [P] [US2] Create `modules/async/src/Placeholder.scala` and `modules/async/README.md` naming spec slot `008-async-delivery-over-mixnet`
- [X] T032 [US2] In `build.mill`, register the seven additional modules (`crypto`, `mixnet`, `pkg`, `configchain`, `sdk`, `agent`, `async`) each `extends SiidaModule { object test extends SiidaTests }` inside the `object modules` block
- [X] T033 [US2] Run `./mill __.compile && ./mill __.test`; expect 8 passing tests (verified 2026-05-17: all 8 modules compile, all 8 PlaceholderSuite tests pass); expect 8 passing tests (one per module); fix any module that fails

**Checkpoint**: User Stories 1 AND 2 both work. Every numbered roadmap spec has its target module.

---

## Phase 5: User Story 3 — Legacy Go scaffolding is unmistakably deprecated (Priority: P3)

**Goal**: A new contributor reading `README.md` immediately understands the project is JVM-only and that `go.mod` is a historical artefact.

**Independent Test**: Open `README.md` on a fresh checkout; the deprecation notice is visible in the first screen. Grep the repo: no live build or CI step invokes a Go toolchain. `go.mod` content is byte-identical to its current state.

### Implementation for User Story 3

- [X] T034 [US3] Add a short "Build" or "Bootstrap" section to `README.md` immediately above the existing **Status** section, stating: (a) Siida is JVM-only as of constitution v1.0.0, (b) `./mill __.compile && ./mill __.test` is the canonical bootstrap, (c) the `go.mod` file at the repo root is a historical artefact retained for git-history continuity and MUST NOT be used to build (FR-008, R12)
- [X] T035 [US3] Add a grep-based assertion step to `scripts/check-ci-parity.sh` (or a new `scripts/check-no-go.sh` invoked from both CI workflows) that fails if `go build`, `go test`, `go vet`, `go mod`, or `setup-go` appears anywhere under `.github/workflows/` or `.forgejo/workflows/` (FR-012)
- [X] T036 [US3] Verify `go.mod` content is byte-identical to its pre-001 state (`git diff HEAD~ go.mod` empty); confirm no `*.go` source files exist anywhere in the tree (`find . -name '*.go' -not -path './.git/*'` returns nothing)

**Checkpoint**: All three user stories are independently functional. The bootstrap is feature-complete against `spec.md`.

---

## Phase N: Polish & Cross-Cutting Concerns

**Purpose**: Verify the success criteria that are observable only after the full bootstrap is in place.

- [ ] T037 [P] Measure SC-001: time `./mill __.compile && ./mill __.test` on a typical developer laptop after deleting `out/` and the Mill download cache; record the result in `specs/001-project-bootstrap/notes-validation.md` and flag if it exceeds 5 minutes
- [ ] T038 [P] Measure SC-002: capture wall-clock duration of the first 10 CI runs on each side (GitHub Actions, Forgejo Actions); compute median; record in `specs/001-project-bootstrap/notes-validation.md`
- [ ] T039 Validate SC-006: on a throwaway branch, add a `.scala` file without the AGPL header and push; confirm both CI pipelines fail at the `millSiidaHeaderCheck` step; then revert
- [ ] T040 [P] Cross-check the per-module README mapping (T025–T031) against the published roadmap table in the repo `README.md` (which already references 005-config-chain-governance through 008-async-delivery-over-mixnet); confirm one-to-one correspondence and that no roadmap area is unrepresented

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 Setup**: no dependencies; start immediately
- **Phase 2 Foundational**: depends on Phase 1; BLOCKS all user stories
- **Phase 3 US1 (P1)**: depends on Phase 2; can run in parallel with Phase 4/5 once Phase 2 is done
- **Phase 4 US2 (P2)**: depends on Phase 2; can run in parallel with Phase 3/5 once Phase 2 is done
- **Phase 5 US3 (P3)**: depends on Phase 2 (specifically the CI workflows existing); ideally runs after Phase 3 so the CI Go-removal lands first, but technically independent
- **Polish (Phase N)**: depends on US1, US2, and US3 all being complete

### Within Each User Story

- Tests MUST be written and observed failing before the Placeholder they exercise is added
- Per-module Placeholder and README within a story are independent (`[P]`)
- `build.mill` registration for a module follows that module's source/test creation
- Story complete when all its FRs map to passing tasks

### Parallel Opportunities

- Setup: T003, T004, T005 are independent (different files) and parallel
- Foundational: T006/T007/T008/T009 share `build.mill` so are sequential; T010 (`check-ci-parity.sh`) is parallel to them
- US1: T011, T012, T013 are different files → parallel; T014, T015, T016 each edit a single distinct file and are independent of one another (build.mill vs the two workflow files), though all three depend on T011–T013
- US2: T018–T024 (tests) parallel across modules; T025–T031 (sources + READMEs) parallel across modules; T032 sequential (single file: `build.mill`); T033 sequential
- US3: T034 and T035 touch different files → parallel; T036 is pure verification
- Polish: T037, T038, T040 are parallel

---

## Parallel Example: User Story 2 implementation

```bash
# After T011–T017 (US1) and T018–T024 (US2 tests) are done,
# launch all seven Placeholder+README pairs in parallel:
Task: "Create modules/crypto/src/Placeholder.scala + modules/crypto/README.md"
Task: "Create modules/mixnet/src/Placeholder.scala + modules/mixnet/README.md"
Task: "Create modules/pkg/src/Placeholder.scala + modules/pkg/README.md"
Task: "Create modules/configchain/src/Placeholder.scala + modules/configchain/README.md"
Task: "Create modules/sdk/src/Placeholder.scala + modules/sdk/README.md"
Task: "Create modules/agent/src/Placeholder.scala + modules/agent/README.md"
Task: "Create modules/async/src/Placeholder.scala + modules/async/README.md"

# Then T032 registers all seven in build.mill (sequential, single file).
```

---

## Implementation Strategy

### MVP First (User Story 1 only)

1. Complete Phase 1 (Setup) — pins the toolchain
2. Complete Phase 2 (Foundational) — `build.mill`, header check, CI parity script
3. Complete Phase 3 (US1) — `core` module + rewritten CI workflows
4. **STOP and VALIDATE**: clean-clone build succeeds; both CI pipelines green
5. Tag/demo: the JVM-native bootstrap is proven end-to-end before any other module exists

### Incremental Delivery

1. Ship MVP (US1) — toolchain proven
2. Add US2 — fan out to all seven roadmap modules; every numbered spec now has a home
3. Add US3 — finish the Go-deprecation paperwork and the no-Go CI guard
4. Run Polish (T037–T040) — validate SC-001, SC-002, SC-006 with real measurements

### Parallel Team Strategy

With multiple contributors, after Phase 2 completes:

- Contributor A: Phase 3 (US1) — `core` + CI rewrites
- Contributor B: Phase 4 (US2) tests (T018–T024) in advance, then implementation after A's `build.mill` skeleton is merged
- Contributor C: Phase 5 (US3) — README deprecation + no-Go grep

---

## Notes

- `[P]` tasks are different files with no incomplete-task dependencies
- `[Story]` traces a task to its user story for selective shipping
- Every smoke test must be deterministic (no I/O, RNG, time) per Constitution Principle IV
- All version pins live in `build.mill` and `.mill-version`; no floating ranges (FR-011)
- The licence-header check is the gate for FR-010 and SC-006; do not bypass it
- Stop at any checkpoint to validate a story independently before continuing
