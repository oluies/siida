# Feature Specification: Project Bootstrap

**Feature Branch**: `001-project-bootstrap`

**Created**: 2026-05-16

**Status**: Draft

**Input**: User description: "Remove the Go scaffolding and stand up the Mill-based Scala 3 + Pekko + Cats Effect 3 build, with placeholder Mill modules for every roadmap area (core, crypto, mixnet, pkg, configchain, sdk, agent, async) and a CI-runnable smoke test on both GitHub Actions and Forgejo Actions."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Clean-clone build proves the stack works (Priority: P1)

A contributor (human or agent) clones the Siida repository onto a fresh
machine, follows the documented bootstrap steps, and observes the full
project compile and a smoke test pass end-to-end. The same flow executes on
both CI services on every push, so no contributor can land a change that
silently breaks the bootstrap path.

**Why this priority**: Without a working bootstrap, no later feature can be
developed, reviewed, or shipped. This is the load-bearing MVP for the entire
roadmap; until it exists, the constitution's "JVM-Native Mixnet Core"
principle is aspirational.

**Independent Test**: Clone the repository to a clean machine, run the
documented build command, and confirm the smoke test exits zero. Push a
trivial change and confirm both CI pipelines go green. Delivers value by
unblocking every subsequent spec (002 onwards).

**Acceptance Scenarios**:

1. **Given** a clean clone of the repository on a developer machine with the
   declared baseline JVM and the committed build launcher, **When** the
   contributor runs the single documented bootstrap command, **Then** the
   project compiles and the smoke test passes within the published time
   budget.
2. **Given** a pull request targeting any branch, **When** CI runs on
   GitHub Actions and on the Forgejo Actions mirror, **Then** both pipelines
   complete the same build-and-smoke-test sequence and both report success.
3. **Given** a contributor on Apple Silicon, **When** they run the bootstrap
   command, **Then** the build succeeds without requiring x86-only tooling
   or hand-installed native binaries.

---

### User Story 2 - Every roadmap area has an obvious home (Priority: P2)

A contributor opening a new spec (002-crypto-pairing, 003-mixnet-server, …)
finds an existing placeholder module whose name unambiguously corresponds to
their feature. They add their code to that module without restructuring the
build or inventing new top-level directories.

**Why this priority**: The constitution's spec-driven workflow (Principle
II) only works if each numbered spec has an obvious target in the codebase.
Pre-creating empty placeholder modules removes a recurring source of
bikeshedding and arbitrary layout decisions in every subsequent feature.

**Independent Test**: For each numbered roadmap area (002–008), open the
repository and locate the placeholder module that future work will fill.
The mapping is unambiguous: one module per area, named for the area, with a
short README pointing at the corresponding spec slot.

**Acceptance Scenarios**:

1. **Given** the roadmap as published in `README.md`, **When** a contributor
   looks for the module corresponding to feature 003 (mixnet-server),
   **Then** exactly one placeholder module is the unambiguous target and its
   README links to `specs/003-*`.
2. **Given** all placeholder modules exist, **When** the full build runs,
   **Then** every placeholder compiles and its smoke test passes (no
   `???`-stubbed-but-broken modules).

---

### User Story 3 - Legacy Go scaffolding is unmistakably deprecated (Priority: P3)

A new contributor browsing the repository sees `go.mod` and immediately
understands from `README.md` that the project is JVM-only and that the Go
file is a vestigial artefact retained for git history. They do not attempt
to build the project with Go tooling.

**Why this priority**: Misleading a contributor into running `go build`
wastes their time and damages first-impression trust. Removing the file
entirely is cleaner, but retention with a clear deprecation note preserves
the lineage record without operational risk.

**Independent Test**: Open `README.md` on a fresh checkout and confirm the
deprecation notice is visible in the first screen of content. Confirm that
no documentation, CI workflow, or build script references Go tooling.

**Acceptance Scenarios**:

1. **Given** the deprecation notice in `README.md`, **When** a new
   contributor reads the project overview, **Then** the JVM-only nature of
   the build is unambiguous and `go.mod` is explicitly marked as a
   historical artefact.
2. **Given** the build configuration, **When** any contributor or CI runner
   executes a build, **Then** no Go toolchain is invoked or required.

---

### Edge Cases

- **Wrong JVM**: contributor runs the build with a JVM older than the
  declared baseline; the build halts with a clear message naming the
  required version, not an obscure bytecode error.
- **Mill launcher missing**: contributor's machine has no Mill installed
  and the committed launcher script is the bootstrap path; the launcher
  must self-install or fetch a pinned Mill version without manual setup.
- **Apple Silicon developer, x86-only CI runner (or vice versa)**: the
  build must produce identical results on both architectures; native
  dependencies introduced later (e.g., gnark-crypto via JNI in feature
  002) are out of scope for this spec but must not be precluded by the
  bootstrap layout.
- **Forgejo Actions runner missing a feature GitHub Actions has**: the
  shared workflow logic must degrade gracefully or the divergence must be
  documented; a green GitHub run with a silently-skipped Forgejo step is
  not acceptable.
- **Smoke test flake**: the smoke test must be deterministic; no
  retry-on-failure shortcut is permitted (Principle IV).
- **Licence-header drift**: a contributor adds a new source file without
  the required licence header; the build must fail rather than allowing
  the omission to compound across modules.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The repository MUST contain a single Mill build descriptor at
  the repository root that defines every placeholder module listed in
  FR-003.
- **FR-002**: The bootstrap build MUST succeed from a clean clone using a
  single documented command, requiring no globally installed Scala or Mill
  tooling beyond a JVM at the declared baseline.
- **FR-003**: The build MUST define one placeholder module per numbered
  roadmap area: `core`, `crypto`, `mixnet`, `pkg`, `configchain`, `sdk`,
  `agent`, `async`. Each module MUST contain at least one compilable
  source file and exactly one passing smoke test.
- **FR-004**: Each placeholder module MUST contain a short `README.md`
  that names the corresponding numbered spec (e.g., `crypto` → 002,
  `mixnet` → 003, `configchain` → 005) and states that the module is a
  placeholder until that spec lands.
- **FR-005**: A continuous-integration workflow for GitHub Actions MUST
  run the bootstrap build and the smoke tests on every push and every
  pull request.
- **FR-006**: A continuous-integration workflow for Forgejo Actions MUST
  run the same logical sequence as FR-005 on every push and every pull
  request, kept in sync with the GitHub workflow.
- **FR-007**: The build MUST succeed on at least one Linux/amd64 CI
  runner and on at least one macOS/arm64 (Apple Silicon) local-developer
  configuration. Apple Silicon coverage in CI is not required by this
  spec, but the bootstrap MUST NOT prevent it.
- **FR-008**: `README.md` MUST contain a deprecation notice for the
  legacy `go.mod` file, stating that the project is JVM-only and that
  the Go file is retained as a historical artefact.
- **FR-009**: The Mill build MUST configure Scala 3 as the language and
  pin a single Scala 3 version used by every module. Pekko and Cats
  Effect 3 MUST be declared as common dependencies even if only a
  trivial reference is present in the placeholder modules, so future
  features inherit the version baseline.
- **FR-010**: The build MUST verify that every source file in every
  module carries the required licence header (AGPL-3.0-or-later for new
  files; preserved original headers for ported files) and MUST fail the
  build on any violation.
- **FR-011**: All Mill dependencies, plugins, and the Mill version
  itself MUST be pinned to specific versions. Floating ranges and
  "latest" are forbidden.
- **FR-012**: Neither CI workflow MUST invoke any Go toolchain, and the
  bootstrap documentation MUST NOT include Go commands.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A contributor on a typical developer laptop with only the
  baseline JVM installed can go from `git clone` to a green smoke-test
  result in under 5 minutes (excluding initial dependency download time
  on first run).
- **SC-002**: Both CI pipelines complete the bootstrap build and the
  smoke tests in under 10 minutes per push, measured as the median of
  the most recent 10 runs.
- **SC-003**: Every roadmap area numbered 002 through 008 has exactly
  one placeholder module that its future spec can target without
  renaming or restructuring.
- **SC-004**: Zero CI failures over the first 20 pushes following merge
  are attributable to flaky bootstrap behaviour (missing dependency,
  non-deterministic test, runner-architecture difference); failures
  from genuinely broken contributor code do not count.
- **SC-005**: A new contributor onboarding for the first time can
  correctly identify the placeholder module corresponding to any
  numbered roadmap area in under 60 seconds, using only the published
  `README.md` and the per-module `README.md` files.
- **SC-006**: A pull request that omits the required licence header on a
  new source file is blocked by CI rather than merged, in 100% of cases.

## Assumptions

- The constitution's choice of Scala 3 + Apache Pekko + Cats Effect 3
  with Mill as the build tool is settled in v1.0.0 and is not
  re-litigated by this spec.
- A long-term-support JVM is the baseline (JVM 21 LTS unless an earlier
  decision in `plan.md` revises this). Later features may raise the
  baseline; this spec does not.
- The committed Mill launcher script is the canonical entry point;
  contributors are not expected to install Mill globally.
- Apple Silicon is a fully supported *developer* platform; Apple
  Silicon CI runners are nice-to-have, not required by this spec.
- The Codeberg remote is not configured yet; remote provisioning is out
  of scope and handled separately.
- `go.mod` is the only Go artefact in the repository (40 bytes, no
  `go.sum`); deprecation in `README.md` is sufficient and no `.go`
  source files need removal.
- The existing GitHub Actions and Forgejo Actions workflow files
  (`.github/workflows/ci.yml`, `.forgejo/workflows/ci.yml`) are
  starting scaffolds and will be rewritten to invoke the Mill build;
  their current content is not load-bearing.
