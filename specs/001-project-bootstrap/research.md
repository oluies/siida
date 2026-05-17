# Phase 0 Research: Project Bootstrap

**Feature**: [spec.md](./spec.md)
**Date**: 2026-05-16
**Status**: Complete — all open questions resolved

This document captures the decisions taken to fill the Technical Context of
`plan.md`. Every question listed in `spec.md`'s Assumptions, every implicit
unknown raised by the constitution-pinned stack, and every concrete version
choice is resolved here.

---

## R1. Scala 3 version

**Decision**: Pin to **Scala 3.6.3** (latest stable on the 3.6.x line).

**Rationale**: 3.6.x is the current stable Scala 3 line. It is the latest
version supported by all Cats Effect 3, Pekko, and http4s artefacts in the
versions we want. Pinning to a specific patch (3.6.3) keeps the bootstrap
reproducible; the next feature that demands a newer compiler can lift the
pin in its own plan.

**Alternatives considered**:
- 3.3.x LTS: longer support window, but several Pekko/CE3 examples and the
  newer scaladoc story are written against 3.6.x. The "JVM-Native Mixnet
  Core" principle gains nothing from staying behind on the compiler.
- 3.7-RC: not stable; would breach FR-011 (pinned versions, no "latest").

---

## R2. Pekko version

**Decision**: Pin to **Pekko 1.1.x** (latest stable 1.1 patch).

**Rationale**: Pekko 1.1 is the current stable line, ApacheSoftwareFoundation
release. It is the AGPL-compatible Akka 2.6.x fork the constitution
mandates (Principle III). All sub-artefacts (`pekko-actor-typed`,
`pekko-stream`, `pekko-persistence`, `pekko-cluster-typed`) ship from the
same 1.1 release train, which simplifies the common dependency block in
the Mill build.

**Alternatives considered**:
- Pekko 1.0.x: older, missing several stability fixes; no benefit to us.
- Akka 2.7+: explicitly forbidden by constitution Principle III (BSL).

---

## R3. Cats Effect 3 version

**Decision**: Pin to **Cats Effect 3.5.x** (latest stable on the 3.5 line).

**Rationale**: 3.5 is the long-standing stable line with the broadest
ecosystem support (munit-cats-effect3, http4s, fs2). The fiber model and
scheduler are mature; we have no requirement that would push us to a
pre-release line.

**Alternatives considered**:
- Cats Effect 3.6 pre-releases: not stable; breaches FR-011.
- Cats Effect 2: end-of-life and not what the constitution names.

---

## R4. Build tool version

**Decision**: Pin to **Mill 0.12.x** (latest stable 0.12 patch), recorded
in a committed `.mill-version` file.

**Rationale**: Mill 0.12 is the stable line; Mill 1.0 had been in flight
but 0.12 remains the recommended production line as of the bootstrap date.
The committed `.mill-version` file is read by the `./mill` launcher to
fetch the exact version on first invocation, satisfying FR-002 (no global
Mill install required).

**Alternatives considered**:
- Mill 1.0 (if released): defer to a later spec; bootstrap should ride the
  stable line.
- sbt: rejected by constitution Principle V.

---

## R5. JVM baseline

**Decision**: **Temurin 21 LTS** (any 21.0.x).

**Rationale**: JVM 21 is the current LTS, supported by Pekko 1.1 and
Cats Effect 3.5. It gives us virtual threads (useful if a later feature
wants Loom-style concurrency at the ingress boundary), pattern matching
support that Scala 3 leverages, and a multi-year support window. Temurin
is the default open-source distribution and is what `setup-java@v4` and
the Forgejo OCI base images both ship.

**Alternatives considered**:
- JVM 17: still supported but missing virtual threads; gains nothing.
- JVM 23 (non-LTS): faster release cadence, but breaches our "stable"
  posture for the bootstrap.

---

## R6. Test framework

**Decision**: **munit 1.x** + **munit-cats-effect3 2.x** for Cats Effect
integration. No ScalaTest, no Specs2.

**Rationale**: munit is small, fast, and produces clean diffs. The
`munit-cats-effect3` companion lets test bodies return `IO[Unit]`, which
matches Principle V's typed-fibre concurrency story. The bootstrap smoke
tests are trivial, so a heavy framework would add dependency surface for
no benefit. ScalaCheck can be added later per-feature if property tests
become useful (002 crypto and 003 mixnet are likely consumers).

**Alternatives considered**:
- ScalaTest: ubiquitous, but larger surface and more "magic"; unjustified
  cost for a placeholder smoke-test layer.
- weaver-test: also CE3-native, but munit has wider community traction
  and simpler output.

---

## R7. Licence-header enforcement

**Decision**: A **small custom Mill task** (`millSiidaHeaderCheck`) that
walks the source tree and verifies every `.scala`/`.java`/`.sc` file
starts with the expected AGPL-3.0-or-later header (for files originated
in this repo) or a recognised upstream BSD-3-clause header (for ported
files). No third-party Mill plugin.

**Rationale**: Constitution Principle III demands licence integrity and
Principle V's Mill rationale prefers a small dependency surface. A
regex-based check is ~50 lines of Scala in `build.mill`, runs in well
under a second, and avoids pulling in any plugin we'd have to audit. The
check is wired as a transitive dependency of every module's `compile`
task, so the build fails before tests run if a header is missing or
malformed.

The header template is committed at `build/licence-headers/agpl.txt`;
the ported-file allowlist is committed at `build/licence-headers/ported.json`.

**Alternatives considered**:
- `de.tototec.de.tobiasroeser.mill-license-header` (or similar
  third-party plugin): adds a transitive dependency and a version we'd
  have to track.
- Pre-commit hook only: would not fail CI on bypass; constitution
  forbids `--no-verify`, but the gate belongs in CI, not just local
  hooks.

---

## R8. CI JVM provisioning

**Decision**:
- **GitHub Actions**: `actions/setup-java@v4` with `distribution: temurin`
  and `java-version: 21`.
- **Forgejo Actions**: a container image that already ships Temurin 21
  (we will pin `eclipse-temurin:21-jdk` from Docker Hub). The current
  workflow uses a Node image — that will be replaced.

**Rationale**: `setup-java@v4` is the canonical first-party action on
GitHub Actions and supports caching the Mill out directory keyed on
`.mill-version`. The Forgejo runner is documented to support standard
OCI images; pinning `eclipse-temurin:21-jdk` removes the need for an
install step inside the job.

**Alternatives considered**:
- Pre-baked GitHub runner JDK: not all runners have a recent enough JVM
  on the right path; `setup-java` is more deterministic.
- A bespoke Docker image for both runners: more flexible but more to
  maintain; defer to a later observability/release-engineering spec.

---

## R9. Module directory layout

**Decision**: Standard Mill layout under a top-level `modules/` directory:

```
modules/<name>/src/         -- main sources
modules/<name>/test/src/    -- test sources
modules/<name>/README.md    -- per-module README pointing at the spec
```

Modules: `core`, `crypto`, `mixnet`, `pkg`, `configchain`, `sdk`,
`agent`, `async`.

**Rationale**: Standard Mill convention; the `modules/` parent keeps
build artefacts visually separate from `specs/`, `.specify/`, `LICENSE`,
etc. at the repo root. Each module is independently buildable
(`./mill modules.mixnet.compile`) which matches Principle II's
spec-per-module discipline.

**Alternatives considered**:
- Putting modules at the repo root (no `modules/` parent): clutters the
  root and conflicts with non-source top-level directories.
- One module per language (`scala/`, `java/`): the project is Scala 3
  end-to-end; not useful.

---

## R10. Common base module trait

**Decision**: Define a `SiidaModule` trait in `build.mill` extending
`ScalaModule` (Mill core) with:

- Scala version (R1)
- Scalac options: `-Wunused:all`, `-Werror`, `-deprecation`,
  `-feature`, `-language:strictEquality` (no `-Xfatal-warnings`: it is
  redundant with `-Werror` in Scala 3, and the redundancy itself becomes
  a fatal error under `-Werror`)
- Common deps: Cats Effect 3 core (R3), Pekko actor-typed and
  stream (R2). Modules opt in to additional Pekko/CE3 modules.
- Test framework wiring: munit + munit-cats-effect3 (R6) in
  `SiidaTests` trait
- The licence-header check (R7) wired as a dependency of `compile`

**Rationale**: Centralising the compiler options and common deps means
every module gets the same lint posture without per-module duplication.
`-Werror` plus `-Wunused:all` enforces Principle IV's discipline at
the compiler level.

**Alternatives considered**:
- Per-module dependency lists: more flexible but invites drift in the
  Scala version and warning posture.

---

## R11. Smoke-test content

**Decision**: Each module ships one `Placeholder` object with a single
`name: String` value (the module's roadmap area) and one munit-cats-effect3
test asserting it equals the expected literal. No I/O, no time, no
randomness, no Pekko system started.

**Rationale**: The smoke test exists to prove the test runner, the Mill
wiring, the dependency resolution, and the CI runner work — nothing
more. Anything richer would belong in the spec that fills the module.
Determinism is trivially satisfied (Principle IV).

**Alternatives considered**:
- "Hello, Pekko" actor smoke test: would prove more, but actor startup
  introduces scheduler timing that could flake in resource-constrained
  CI runners; defer to 003.

---

## R12. Go scaffolding disposition

**Decision**: Retain `go.mod` unmodified. Add a deprecation note to the
**Status** section of `README.md` (or a new short section above
**Lineage and licence**). Delete the Go-flavoured CI workflows.

**Rationale**: Matches the user's stated preference. `go.mod` carries
no functional weight (40 bytes, no `go.sum`) and removing it would
forfeit a small git-history breadcrumb. The deprecation note prevents
confusion. CI workflows are rewritten to invoke Mill, not preserved.

**Alternatives considered**:
- Delete `go.mod`: cleaner but loses the breadcrumb; the user explicitly
  chose retention.

---

## R13. CI synchronisation between GitHub and Forgejo

**Decision**: Keep two parallel workflow files (`.github/workflows/ci.yml`
and `.forgejo/workflows/ci.yml`) that perform the same logical steps
in the same order. A short `scripts/check-ci-parity.sh` walks both files
and asserts the step names and order match; this script is itself a
Mill `T.command` and is invoked in both CI workflows so any drift
breaks the build on whichever side is out of date.

**Rationale**: Forgejo Actions is *mostly* compatible with GitHub
Actions but not identical (no marketplace; some actions need
substitution). A literal symlink isn't viable. A parity check is the
cheapest way to enforce the constitution's "both must stay green" rule
and to catch divergence in review rather than at a production cut-over.

**Alternatives considered**:
- One workflow file symlinked: blocked by Forgejo/GitHub-Actions
  differences in `uses:` resolution.
- Manual review only: human discipline fails over time; the constitution
  treats this as a quality gate.

---

## Open questions deferred to later specs

- **Apple Silicon CI coverage**: not required by 001 (spec FR-007).
  Revisit during 002 (gnark-crypto JNI work would need cross-arch CI).
- **Reproducible-build verification**: the constitution mentions
  reproducible builds as a SHOULD; concrete tooling (e.g.,
  `reproducible-builds.org` diffoscope harness) is deferred to a future
  release-engineering spec.
- **Telemetry opt-in for the Mill build itself**: Mill's anonymous
  usage stats — verify and disable if present, defer otherwise.
