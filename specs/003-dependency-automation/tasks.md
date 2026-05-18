---
description: "Task list for 003-dependency-automation"
---

# Tasks: Dependency Automation (Scala Steward)

**Input**: Design documents from `/specs/003-dependency-automation/`

**Prerequisites**: plan.md (required), spec.md (required for the
single user story)

**Tests**: Not requested. The spec's US1 Independent Test is a
manual validation procedure (downgrade a pin, observe Steward PR);
no automated test suite is added.

**Organization**: One user story; tasks are flat.

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: Different files, no dependency
- Setup, Foundational, Polish phases omit the `[Story]` label
- Every task names exact file paths

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Add the Steward workflow and config files.

- [X] T001 [P] Create `.github/workflows/scala-steward.yml`: GitHub Actions workflow with `schedule: '0 0 * * 1'` (Monday 00:00 UTC) plus `workflow_dispatch`; one job using `scala-steward-org/scala-steward-action@v2`; reads `secrets.STEWARD_TOKEN || secrets.GITHUB_TOKEN` so a fine-grained PAT triggers downstream CI on bot PRs when present (FR-001, FR-007)
- [X] T002 [P] Create `.scala-steward.conf` at repo root: pin `org.apache.pekko` to `1.1.`, `org.scala-lang.scala3-library_3` to `3.6.`, `org.typelevel.cats-effect_3` to `3.5.`; ignore preview / RC / milestone versions (`3.7.0-RC*`, `*-M*`, `*-SNAPSHOT`); set weekly pull-request frequency; include a commit-message template naming artefact + version delta (FR-004, FR-005)
- [X] T003 [P] Edit `README.md` to renumber the roadmap table: `003-mixnet-server` → `004`, `004-pkg-keybootstrap` → `005`, `005-config-chain-governance` → `006`, `006-client-sdk` → `007`, `007-agent-messaging` → `008`, `008-async-delivery-over-mixnet` → `009`; update the "Past `008` likely lives a `009-chat-client` and an `010-observability`" sentence to reflect the new numbering (009-chat-client → 010, 010-observability → 011); insert a new `003 dependency-automation` row above the renumbered `004-mixnet-server` (FR-008)

---

## Phase 2: Validation (Manual, post-merge)

**Purpose**: Confirm the pipeline works end-to-end.

- [ ] T004 _(manual, post-merge)_ Trigger the workflow once via `gh workflow run scala-steward.yml` and verify it completes successfully on GitHub. If Maven Central currently has any newer-version dep, expect a PR to land. If not, the run finishes green with no PR opened — also a success.
- [ ] T005 _(manual, optional)_ Set `STEWARD_TOKEN` as a repository secret (fine-grained PAT with `contents: write` + `pull-requests: write`) so CI runs on Steward-opened PRs. Without it, the maintainer must close-and-reopen Steward PRs to trigger CI.

---

## Dependencies & Execution Order

All Phase 1 tasks are independent (`[P]`) — different files. They
can land in a single PR with three file changes.

Phase 2 tasks happen after the PR merges; they're operational
checks rather than implementation steps.

---

## Implementation Strategy

This is a single-PR feature: T001 + T002 + T003 land together in
one commit. The PR opens against `main` and goes through the
standard `ci.yml` gate. The new workflow does not affect the
parity check (it's a separate file outside the parity-script's
read list).

---

## Notes

- `.scala-steward.conf` HOCON format is documented at
  <https://github.com/scala-steward-org/scala-steward/blob/main/docs/repo-specific-configuration.md>;
  if Steward's config format changes upstream, the file may need
  adjusting.
- The Steward workflow is opt-in for the maintainer to set
  `STEWARD_TOKEN`; without it, CI does not run on bot PRs. This is
  a documented limitation (spec.md FR-007, plan.md "Maintainer
  notes").
- Per the user's directive ("ignore go we are deleting go later"),
  the cgo shim under `modules/crypto/native/` is NOT covered by
  this spec. No Dependabot for Go, no Renovate, no manual bumps
  driven by tooling — gnark-crypto stays pinned manually until 002's
  Go path either matures or is removed by a future spec.
