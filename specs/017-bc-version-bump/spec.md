# Feature Specification: Bouncy Castle Version Bump — close the FIPS 203 / 204 gap

**Feature Branch**: `017-bc-version-bump`

**Created**: 2026-05-20

**Status**: Draft

**Input**: Spec 016's audit (PR #35, merged 2026-05-20) established
that BC 1.78.1 ships NIST Round-3 Kyber/Dilithium, not the
finalised FIPS 203 / 204 standards. The baseline-snapshot harness
documents the gap (0/25 ML-KEM keyGen, 25/25 ML-KEM encap, 25/25
ML-KEM decap, 0/25 ML-DSA keyGen, 0/15 ML-DSA sigGen). This spec
closes that gap by bumping BC to the latest available release.

## Why this spec exists

The 016 audit is a diagnostic instrument; it surfaces the
conformance gap but does not fix it. Three follow-up paths were
identified in `specs/016-audit-pq-conformance/notes-conformance.md`:

1. **Bump BC** to a version that ships FIPS 203 / 204
   finalisation — small, mechanical, leverages the 016 audit
   directly as the verification step.
2. **Switch to `bcfips-jdk18on`** — not yet viable; bcfips does
   not ship ML-KEM / ML-DSA as of 2026-05.
3. **Switch to a different PQ provider** (liboqs, AWS-LC,
   Cloudflare CIRCL via JNI) — larger architectural change;
   reintroduces 002's per-arch matrix complexity.

This spec commits to **path 1** as the lowest-risk, highest-
leverage move. Bcfips and alternate providers remain in the
backlog as separate specs if and when needed.

The audit suite from 016 is the verification mechanism: bump BC,
re-run the audit, update the baseline constants to the new
result. If the new BC produces all-pass on every vector set, the
gap is closed. If only some vectors pass, the report documents
the residual gap and (a) decides whether 017 lands as-is or (b)
escalates to a downstream architectural switch.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Bump BC to the latest release and re-verify conformance (Priority: P1)

A maintainer wants to close the FIPS 203 / 204 gap surfaced by
the 016 audit. They bump `org.bouncycastle:bcprov-jdk18on` from
`1.78.1` to the latest available release on Maven Central, run
the 016 audit suites, and observe what changes.

**Why this priority**: P1 because every downstream PQ spec (012
already implemented, 013 / 015 pending implementation) currently
ships against a non-FIPS-conformant primitive. Until this gap
closes, any interop claim with FIPS 203 / 204 counterparties is
false. Closing it before implementing 013 / 015 means downstream
code lands against a conformant baseline.

**Independent Test**:

```sh
./mill modules.crypto.test --testOnly siida.crypto.audit.MlKem768ConformanceSuite \
                                       siida.crypto.audit.MlDsa65ConformanceSuite
```

reports green with the **updated baselines reflecting the new BC
version's results**. The baseline constants in
`MlKem768ConformanceSuite.scala` and `MlDsa65ConformanceSuite.scala`
are updated as part of this PR.

**Acceptance Scenarios**:

1. **Given** `bcprov-jdk18on:1.78.1` in `build.mill`,
   **When** the maintainer changes it to the latest release (1.84
   as of 2026-05-20) and runs the audit suites,
   **Then** the audit fails with "baseline DRIFT" messages
   pointing at the new observed counts.
2. **Given** the audit failure messages,
   **When** the maintainer updates the `baseline*` constants in
   the two audit suites to the new observed counts,
   **Then** `make check` passes and the new baseline is locked.
3. **Given** the updated baseline,
   **When** the maintainer updates
   `specs/016-audit-pq-conformance/notes-conformance.md` with
   the new BC version's audit results,
   **Then** the audit trail reflects the change.

### User Story 2 — If a gap remains, document and decide (Priority: P1)

If bumping to the latest BC still leaves some ACVP vectors
failing (e.g., ML-DSA still missing ctx support, or some
parameter set still on Round 3), the spec must reach an explicit
decision rather than silently shipping with a partial fix.

**Why this priority**: P1 because a half-fixed conformance state
is worse than a fully-documented broken state — reviewers might
assume all primitives conform when only some do.

**Independent Test**: The updated
`specs/016-audit-pq-conformance/notes-conformance.md` (or a new
`notes-bump.md` under `017-bc-version-bump/`) explicitly
enumerates which primitives are conformant after the bump and
which (if any) are not, with the same level of detail as 016's
report.

**Acceptance Scenarios**:

1. **Given** an audit result after the bump where all 5 tests
   show 25/25 or 15/15,
   **When** the maintainer writes the report,
   **Then** it states "BC <new-version> is FIPS 203 / 204
   conformant for ML-KEM-768 (all paths) and ML-DSA-65 (all
   paths). 017 closes the gap end-to-end."
2. **Given** an audit result where some vectors still fail,
   **When** the maintainer writes the report,
   **Then** it lists the residual gaps, the BC-side root cause
   (e.g., ctx parameter not implemented), and a recommendation
   for the next remediation spec (e.g., a small Scala-layer
   ctx-prefix wrapper, or escalation to liboqs).

### Edge Cases

- **BC bump triggers source-incompatibilities**: BC's API has
  been stable for ML-KEM / ML-DSA since 1.78 introduced them.
  If a 1.78 → 1.84 bump renames classes or alters constructors,
  the bump PR includes the minimal source updates to
  `MlKem.scala` and any new wrappers needed by 013.
- **License regression**: BC's licence is MIT (Bouncy Castle
  Project). Any newer version is verified against `LICENCE` /
  `NOTICE` rules (Principle III).
- **Transitive dependency surprise**: BC sometimes brings in
  small auxiliary artefacts. The bump verifies via `./mill
  modules.crypto.resolvedIvyDeps` that no surprise transitive
  deps are introduced.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The bump MUST target the latest stable
  `bcprov-jdk18on` release on Maven Central at the date of the
  bump (1.84 as of 2026-05-20).
- **FR-002**: The bump PR MUST update **only**:
  - `build.mill`: the version literal in `modules.crypto.ivyDeps`
  - The audit-suite baseline constants
  - `specs/016-audit-pq-conformance/notes-conformance.md` (or a
    new `017-bc-version-bump/notes-bump.md` appendix)
  - The roadmap table in `README.md` (insert 017)
  No other production-code changes. If wrapper code in `MlKem.scala`
  needs touching due to BC API drift, that change is in-scope
  but explicitly minimal — no new public API surface.
- **FR-003**: The bump PR MUST pass `make check` end-to-end —
  headers + compile + test + ci-parity — with the audit suites
  asserting the new baseline.
- **FR-004**: If any audit vector set still fails after the
  bump (e.g., ML-DSA-65 sigGen if BC still lacks ctx parameter),
  the report MUST explicitly call this out as a residual gap
  with a named follow-up plan (next spec number, e.g.,
  018-ml-dsa-ctx-wrapper or 018-switch-to-liboqs).
- **FR-005**: The `NOTICE` file MUST be re-verified to ensure
  Bouncy Castle attribution is still correct for the bumped
  version (licence text unchanged across BC 1.78 → 1.84, but
  verifying is cheap insurance).
- **FR-006**: The Scala Steward configuration
  (`.scala-steward.conf`) MUST NOT be loosened to "auto-accept
  BC bumps" — every BC bump triggers the 016 audit's baseline
  DRIFT failure, which forces a human review. That's the
  intended behaviour, not an annoyance to suppress.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: After the bump, the audit suites report either
  all-pass (25/25, 25/25, 25/25, 25/25, 15/15) or a documented
  partial-pass state. There is no ambiguous "some other number"
  outcome — the report enumerates exactly what each vector set
  shows.
- **SC-002**: `make check` exits 0 on darwin-arm64 and on the
  linux-amd64 CI runner.
- **SC-003**: A reviewer reading the updated
  `notes-conformance.md` (or `notes-bump.md`) can answer in
  under 60 seconds: "Is Siida's PQ stack FIPS 203 / 204
  conformant after this PR? If not, what remains?"
- **SC-004**: No new dependencies introduced. BC remains the
  only PQ provider; the same `bcprov-jdk18on` artefact, just at
  a newer version.
- **SC-005**: If 013 / 015 implementation work was planned
  imminently, this bump unblocks it cleanly — downstream PRs
  can rely on the new BC version's behaviour as the conformance
  baseline.

## Assumptions

- The 016 audit suite is in place on `main` (PR #35 merged) and
  the baseline-snapshot pattern is the gate. If the audit is
  somehow disabled before this PR, restore it before bumping.
- BC 1.79+ tracks the FIPS 203 / 204 finalisation as expected
  per its release-notes convention. If the bump reveals that
  even BC 1.84 ships Round-3 algorithms, the spec escalates to
  US2's "document and decide" path and a downstream switch spec.
- The bump is a single PR. If complications arise (BC API drift,
  unexpected test failures unrelated to the audit, transitive
  dep surprises), the PR may grow modestly; if it would balloon
  into multi-week work, the spec triggers a re-scoping
  conversation before merging.
- BC's licence (MIT, Bouncy Castle Project) does not change
  between 1.78 and 1.84. Verified by checking the `NOTICE` /
  `LICENCE` text in the released jar.
- This spec is NOT a switch to `bcfips-jdk18on` or to a non-BC
  provider. Those remain backlog items if 017 is insufficient.
