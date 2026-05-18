# Feature Specification: Dependency Automation (Scala Steward)

**Feature Branch**: `003-dependency-automation`

**Created**: 2026-05-18

**Status**: Draft

**Input**: User description: "Set up Scala Steward to open weekly PRs bumping JVM dependencies. Ignore the Go side of the build (the cgo shim under modules/crypto/native/) per maintainer instruction — that subsystem's automation, or its removal, will be handled by a future spec."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Weekly dependency-bump PRs land for review (Priority: P1)

A new patch or minor release of a Siida JVM dependency (Pekko, Cats
Effect 3, Scala 3, Mill, JNA, munit, …) is published to Maven Central.
Within a week, an automated bot opens a pull request against `main`
bumping the relevant pin in `build.mill` (or `.mill-version`). The PR
runs the standard CI gate; a human reviewer reads the diff, decides
whether to merge, and either merges or closes.

**Why this priority**: Constitution FR-011 forbids floating ranges
("All Mill dependencies, plugins, and the Mill version itself MUST be
pinned to specific versions"). Pinning without automated bump pressure
means the project silently drifts away from upstream security fixes
and ecosystem patches. The bot turns a slow drift into a visible
review cadence.

**Independent Test**: Bump a recent Steward-watched dep to a version
older than what's on Maven Central (e.g., temporarily edit `Versions.munit`
in `build.mill` from `"1.0.4"` to `"1.0.3"`), push to a branch, and
trigger the Scala Steward workflow manually via `workflow_dispatch`.
Expect a PR within minutes proposing the upgrade back to `"1.0.4"`.
After the test, revert.

**Acceptance Scenarios**:

1. **Given** a Siida JVM dep is one patch behind upstream, **When**
   the scheduled Scala Steward workflow runs (Monday 00:00 UTC) or
   is dispatched manually, **Then** a PR is opened bumping the pin
   to the latest patch on the same minor line, with a commit
   message that names the artefact and both versions.
2. **Given** a Steward PR is open, **When** the regular `ci.yml`
   pipeline runs against it, **Then** the standard gates apply
   (headers + compile + test + ci-parity); the PR is mergeable only
   if all gates pass.
3. **Given** Pekko publishes a 1.2.0 (a minor bump that the
   constitution treats as a stack change), **When** the workflow
   runs, **Then** the PR is created but the `.scala-steward.conf`
   pin constraint causes the PR to be marked or labelled so a
   reviewer notices it requires elevated review per Principle V.
4. **Given** a contributor has set `STEWARD_TOKEN` as a repository
   secret to a fine-grained personal access token, **When** Steward
   opens a PR, **Then** CI runs on that PR (the default
   `GITHUB_TOKEN` does not trigger downstream workflows; a PAT does).

### Edge Cases

- **Steward proposes a major version bump** (e.g., JNA 5.x → 6.x):
  PR is opened normally; the reviewer rejects or accepts manually.
  The `.scala-steward.conf` does not block majors so the human stays
  in the loop.
- **Scala 3 preview / RC versions** (e.g., 3.7.0-RC1): explicitly
  ignored by `.scala-steward.conf`; we do not run on incubator
  releases.
- **Steward sees the Mill version pin in `.mill-version`**: handled
  by Steward natively; expect a PR when Mill 0.12.6 lands.
- **A bump causes CI to fail**: PR sits open with a red check; the
  reviewer decides whether to fix the build or wait for upstream.
- **Network outage during the scheduled run**: workflow retries on
  the next schedule (weekly cadence is forgiving).
- **A dep changes group/artefact ID upstream** (rename, fork): the
  PR will not happen automatically. This requires a manual update
  on Siida's side.
- **Steward proposes bumping a dep we deliberately pin to a
  pre-release** (none today, but conceivable): pin in
  `.scala-steward.conf` to disable that specific bump.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: A scheduled GitHub Actions workflow MUST run Scala
  Steward against the repository on a weekly cadence (Monday 00:00
  UTC) and on `workflow_dispatch` for manual runs.
- **FR-002**: Scala Steward MUST inspect the JVM build configuration
  (`build.mill`, `.mill-version`) and open pull requests against
  `main` proposing version bumps for any JVM dependency that has a
  newer version available on Maven Central.
- **FR-003**: Scala Steward MUST NOT inspect or attempt to bump the
  Go module under `modules/crypto/native/go.mod` (the cgo shim's
  upstream is gnark-crypto and is managed separately; the Go path
  may be removed entirely in a future spec).
- **FR-004**: Scala Steward configuration (`.scala-steward.conf`)
  MUST pin updates within constitutional bounds: stay on the Pekko
  1.1.x line, the Scala 3.6.x line, and the Cats Effect 3.5.x line
  by default. Bumps within these lines proceed; bumps that would
  cross a line are still proposed but a reviewer must explicitly
  approve them.
- **FR-005**: Scala Steward configuration MUST ignore pre-release
  / RC / milestone versions (e.g., `3.7.0-RC*`, `*-M*`, `*-SNAPSHOT`).
- **FR-006**: Opened Steward PRs MUST pass the standard `ci.yml`
  gates (`make check`) before being mergeable; no separate
  Steward-specific CI gate is introduced.
- **FR-007**: Documentation MUST exist (in this spec's `plan.md` or
  a short README under `.github/` or the repo's main `README.md`)
  describing: (a) how to set the optional `STEWARD_TOKEN` PAT
  secret so CI runs on Steward PRs, (b) how to manually trigger the
  workflow via `gh workflow run`, (c) where to find `.scala-steward.conf`
  and how to amend it when the project pins move.
- **FR-008**: The repository's published roadmap (in `README.md`)
  MUST be updated to reflect that 003 is now `dependency-automation`,
  with the previous `003-mixnet-server` and subsequent specs
  renumbered up by one (003→004, 004→005, 005→006, 006→007, 007→008,
  008→009, plus sketched 009→010 and 010→011).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Within 14 days of merging this spec, at least one
  Scala Steward PR is opened against the repository (validates the
  end-to-end pipeline). If Maven Central has no newer versions of
  any pinned dep within the 14-day window, the test-bump procedure
  from US1's Independent Test is run instead and counts as
  satisfaction.
- **SC-002**: The licence-header check (`make headers`) and the
  parity script (`make ci-parity`) both continue to pass after this
  spec lands; the new workflow does not perturb existing gates.
- **SC-003**: A reviewer reading a Steward PR can decide in under
  60 seconds whether to merge it, based on (a) the PR title
  identifying artefact + version delta, (b) the CI checkmark, and
  (c) the diff being a single-line version change.
- **SC-004**: Zero Steward PRs propose bumps that violate
  constitutional pins without an accompanying warning or label that
  signals elevated review is required (FR-004 working as intended).

## Assumptions

- The constitution v1.0.0 stack pins (Scala 3.6.x, Pekko 1.1.x,
  Cats Effect 3.5.x, Mill 0.12.x) hold; Scala Steward is configured
  to respect them.
- Scala Steward's GitHub Action (`scala-steward-org/scala-steward-action@v2`)
  is mature and Apache-2.0-licensed, suitable for use under the
  constitution's Principle III licence policy.
- The default `GITHUB_TOKEN` is acceptable for opening Steward PRs
  but does NOT trigger downstream workflows (CI). A `STEWARD_TOKEN`
  secret (a fine-grained PAT) is the recommended path for getting
  CI to run on bot PRs; if it is absent, a maintainer must
  manually trigger CI by pushing an empty commit to the PR branch
  or closing+reopening the PR.
- The Go module under `modules/crypto/native/go.mod` is excluded
  from automation. If 002's gnark-crypto pin needs bumping, a human
  opens a PR. A future spec may replace the cgo path entirely; this
  spec does not commit to a timeline.
- No central / hosted Scala Steward bot is used (e.g.,
  `github.com/scala-steward-org/scala-steward`'s shared instance);
  the workflow runs inside the Siida repository so the audit trail
  is local. This means the maintainer is responsible for the Steward
  runs and their bills against GitHub Actions minutes.
- Forgejo Actions does NOT run the Steward workflow; it lives on
  GitHub only. The dual-CI parity script ignores it because the
  parity check reads only `ci.yml` files by exact name.
