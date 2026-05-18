# Implementation Plan: Dependency Automation (Scala Steward)

**Branch**: `003-dependency-automation` | **Date**: 2026-05-18 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/003-dependency-automation/spec.md`

## Summary

Add a weekly Scala Steward GitHub Actions workflow plus a
`.scala-steward.conf` that respects the constitution's JVM stack
pins (Pekko 1.1.x, Scala 3.6.x, Cats Effect 3.5.x). The Go side of
the build (the cgo BN254 shim from 002) is explicitly excluded;
gnark-crypto bumps remain manual.

Two new files, one renumbered roadmap, no Scala or Mill changes
needed.

## Technical Context

**Language/Version**: N/A — this spec adds CI tooling, not code.
The workflow yaml runs on GitHub-hosted `ubuntu-latest` runners.

**Primary Dependencies** (CI only):
- `scala-steward-org/scala-steward-action@v2` (Apache-2.0)
- Standard `actions/checkout@v4`

**Storage**: N/A.

**Testing**: No new automated tests. Manual validation per
`spec.md` US1 Independent Test: temporarily downgrade a pin,
trigger the workflow via `workflow_dispatch`, observe the PR.

**Target Platform**: GitHub-hosted runners only. Forgejo Actions
does not run this workflow.

**Project Type**: Repository tooling / CI augmentation.

**Performance Goals**: A Steward run completes in under 5 minutes
for a repo this size; weekly cadence makes total time negligible.

**Constraints**:
- Constitution Principle III: every new dep / Action must be
  licence-compatible. Scala Steward action is Apache-2.0; the bot
  it runs reaches Maven Central (no Siida code uploaded).
- Constitution Principle II: this is a numbered spec; the
  inserted slot 003 means renumbering the rest of the published
  roadmap (FR-008).

**Scale/Scope**: Two new files (`.github/workflows/scala-steward.yml`,
`.scala-steward.conf`), two edited files (`README.md` for the
roadmap, optional README-section for the maintainer note).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### Principle I — Metadata Privacy is Non-Negotiable

**Pass.** No traffic-carrying code introduced. The workflow reaches
Maven Central and opens GitHub PRs; no user data is logged or
exposed. Re-check post-design: trivially still passes.

### Principle II — Spec-Driven, Numbered Feature Workflow

**Pass.** Lives under `specs/003-dependency-automation/` per
convention. Renumbers `README.md`'s roadmap so the inserted slot
is reflected (FR-008): `003-mixnet-server` → `004`,
`004-pkg-keybootstrap` → `005`, `005-config-chain-governance` →
`006`, `006-client-sdk` → `007`, `007-agent-messaging` → `008`,
`008-async-delivery-over-mixnet` → `009`. Sketched future slots
also bump.

### Principle III — Licence Integrity (AGPL-3.0-or-later Compatible Only)

**Pass.** `scala-steward-org/scala-steward-action` is Apache-2.0
and runs on GitHub-hosted runners; nothing distributed to users.
The action itself does not become a transitive dep of Siida
binaries.

### Principle IV — Test-First with Deterministic Rounds (NON-NEGOTIABLE)

**N/A in the usual sense** (no rounds, no privacy-relevant code).
The manual validation step in `spec.md` US1 Independent Test is the
deterministic check that the pipeline works.

### Principle V — JVM-Native Mixnet Core (Scala 3 + Pekko + Cats Effect 3)

**Pass.** No changes to the JVM stack. The workflow does not write
to `build.mill` itself; it opens PRs that propose changes for human
review. Pinning constraints in `.scala-steward.conf` keep automatic
bumps within the constitutional stack lines.

### Cross-cutting: Security & Threat Model

**Pass.** The Scala Steward action runs in a GitHub-hosted runner
under the project's `GITHUB_TOKEN`. Optional `STEWARD_TOKEN` PAT
is opt-in via repo secrets; documented in plan.md and spec.md
Assumptions. No secrets are exposed in workflow logs (Actions
masks them by default).

### Cross-cutting: Development Workflow & Quality Gates

**Pass.** New workflow is SEPARATE from the per-PR `ci.yml` gates;
parity script ignores it (reads only `.github/workflows/ci.yml` and
`.forgejo/workflows/ci.yml` by exact name). Steward-opened PRs
must pass the standard gates before being mergeable.

### Re-check after Phase 1 design

No `data-model.md` or `contracts/` are required — this spec
introduces no entities and no Siida API surface. The "contract" is
the GitHub Actions workflow file and the Steward config, both of
which are self-documenting. **PASS.**

## Project Structure

### Documentation (this feature)

```text
specs/003-dependency-automation/
├── plan.md              # This file
├── spec.md              # Feature specification
├── checklists/
│   └── requirements.md  # Spec quality checklist
└── tasks.md             # Phase 2 output (created by /speckit-tasks)
```

`research.md`, `data-model.md`, `quickstart.md`, and `contracts/`
are intentionally omitted: zero implementation alternatives
(`scala-steward-org/scala-steward-action` is the canonical choice),
zero domain entities, zero external API surface. Per the plan
template: "Skip if project is purely internal (build scripts,
one-off tools, etc.)".

### Source Code / Tooling (repository root, additions only)

```text
.github/workflows/scala-steward.yml   # NEW: weekly + workflow_dispatch
.scala-steward.conf                   # NEW: pins respect constitution
README.md                             # EDITED: roadmap table renumbered
```

**Structure Decision**: Pure tooling addition. Two new files and one
renumber. The workflow file lives alongside the other GitHub Actions
workflows under `.github/workflows/`, and the Steward config lives
at the repository root because Steward looks for it there by default.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

Constitution Check passed with no violations. The only project-level
change of note is the roadmap renumber, which is documented
explicitly in FR-008.

## Maintainer notes (post-merge)

- **CI runs on Steward PRs**: by default the `GITHUB_TOKEN` does not
  trigger downstream workflows on Steward-opened PRs. Set
  `STEWARD_TOKEN` (a fine-grained personal access token with
  `contents: write` + `pull-requests: write` scoped to this repo) as
  a repository secret to enable CI on bot PRs. The workflow already
  reads `secrets.STEWARD_TOKEN || secrets.GITHUB_TOKEN`.
- **Manual trigger**: `gh workflow run scala-steward.yml`.
- **Schedule**: Monday 00:00 UTC. Cron expression in the workflow
  yaml; change it there if a different cadence becomes useful.
- **Disabling temporarily**: comment out the `schedule:` block; the
  `workflow_dispatch` entry keeps manual runs available.
- **Adding a new pin constraint**: edit `.scala-steward.conf`,
  commit, push. Steward reads the file on each run.
