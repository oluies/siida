# Implementation Plan: PQ Conformance Audit

**Branch**: `016-audit-pq-conformance` | **Date**: 2026-05-20 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/016-audit-pq-conformance/spec.md`

## Summary

Diagnostic-only spec: verify Bouncy Castle's ML-KEM-768 and ML-DSA-65
match NIST FIPS 203 / 204 byte-for-byte. Produces a conformance
report + a CI-enforced test suite that catches regressions on future
BC bumps. No primitive switching; no implementation changes outside
the audit suite.

Two new test files (audit suites), one resources directory (NIST
ACVP vectors), one written report. The test suite is a permanent
guardrail — if a future Steward bump changes BC's output, CI fails
and the report gets a new entry.

## Technical Context

**Language/Version**: Scala 3.6.4 / JDK 21 LTS (inherited).

**Primary Dependencies**:
- `org.bouncycastle:bcprov-jdk18on:1.78.1` (already in service from 012)
- `org.scalameta::munit:1.3.0` (already in service)
- JSON parsing: use the JDK's built-in `java.util.stream.JsonReader`-equivalent
  — actually Scala 3 doesn't have one in stdlib. Options: add a small JSON
  dep (e.g., `io.circe::circe-core` or `org.json4s`), OR hand-parse the ACVP
  format (manageable since the schema is simple), OR use `upickle` which
  is small and already on Maven Central. **Decision pending plan tasks**:
  default to hand-parse to avoid a new dep.

**Storage**: Read-only — NIST ACVP JSON vector files committed under
`modules/crypto/test/resources/acvp/`.

**Testing**: Two munit suites under `siida.crypto.audit.*`:
- `MlKem768ConformanceSuite` — keyGen / encapDecap vectors
- `MlDsa65ConformanceSuite` — keyGen / sigGen / sigVer vectors

**Target Platform**: Linux/amd64, Linux/arm64, Darwin/arm64. No new
runtime concerns; pure-Java tests.

**Project Type**: Test-suite / audit feature. No production-code
additions.

**Performance Goals**:
- Full ACVP run for ML-KEM-768 under 30 seconds on a typical laptop
- Full ACVP run for ML-DSA-65 under 60 seconds (signature gen is
  slower)

**Constraints**:
- Audit suites MUST be part of `make test` (not opt-in / skipped)
  so future BC bumps trigger them automatically
- Vector files are CC0 (NIST public release); committable
- Test resources MUST NOT exceed ~20 MB total (down-select the
  ACVP corpus if needed)

**Scale/Scope**:
- ~2 new Scala files (audit suites)
- ~2-5 MB of committed ACVP vectors (parameter set 3 only)
- 1 conformance report
- 0 production-code changes

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### Principle I — Metadata Privacy is Non-Negotiable (v2.0.0)

**Pass.** Audit is read-only diagnostic; no metadata-touching
code introduced.

### Principle II — Spec-Driven, Numbered Feature Workflow

**Pass.** 016 is the audit slot, inserted at the next available
numbered position. Observability (previously sketched at 016)
bumps to 017.

### Principle III — Licence Integrity

**Pass.** No new runtime dependencies (BC already in service).
NIST ACVP vectors are CC0; compatible with AGPL.

### Principle IV — Test-First with Deterministic Rounds

**Pass.** Audit IS the test layer. Determinism comes from the
NIST vectors themselves (each ACVP entry has a fixed seed +
expected output).

### Principle V — JVM-Native Mixnet Core

**Pass.** Pure-Java; no JNI.

### Cross-cutting: Security & Threat Model (v2.0.0)

**Pass.** Audit informs the threat model — confirming
interoperability with FIPS 203 / 204 counterparties supports the
constitution's "European certification anchoring" stance.

### Cross-cutting: Development Workflow & Quality Gates

**Pass.** `make check` covers the new suites; no CI workflow
changes.

### Re-check after Phase 1 design

No new violations. `contracts/` for an audit spec is minimal —
the "contract" is the ACVP format itself, which is NIST's. No
in-tree contract docs needed beyond the vector-format note in
research R3 + R7. **PASS.**

## Project Structure

### Documentation (this feature)

```text
specs/016-audit-pq-conformance/
├── plan.md
├── spec.md
├── research.md
├── checklists/
│   └── requirements.md
├── tasks.md                    # (Phase 2 output)
└── notes-conformance.md        # written audit result; lands when impl runs
```

### Source Code (additions only)

```text
modules/crypto/
├── test/
│   ├── src/
│   │   ├── siida/crypto/audit/
│   │   │   ├── AcvpVectorReader.scala       # NEW — JSON parser for ACVP vector files
│   │   │   ├── MlKem768ConformanceSuite.scala  # NEW
│   │   │   └── MlDsa65ConformanceSuite.scala   # NEW
│   └── resources/
│       └── acvp/
│           ├── ml-kem-768-keygen.json       # NEW (committed; CC0)
│           ├── ml-kem-768-encapdecap.json   # NEW
│           ├── ml-dsa-65-keygen.json        # NEW
│           ├── ml-dsa-65-siggen.json        # NEW
│           └── ml-dsa-65-sigver.json        # NEW
```

`README.md` roadmap table also updates: insert 016 audit-pq-conformance;
sketched observability becomes 017.

**Structure Decision**: Audit code lives under a new `siida.crypto.audit`
package, separate from `siida.crypto.api` and `siida.crypto.internal`.
This makes it clear at the package level that audit code is
verification, not production primitives.

## Complexity Tracking

No constitutional violations. Items noted for the audit trail:

| Item | Note | Why not a violation |
|---|---|---|
| Committing ~5 MB of NIST ACVP vectors | Significant test-resource size | CC0-licensed; one-time commit; provides cross-implementation verification that no in-tree fixed-seed KAT can offer |
| Hand-rolled JSON parser for ACVP format | Reinvents wheel | Avoids adding a JSON dep (`circe`, `upickle`, etc.) for a one-off use case; ACVP format is simple enough |
| Audit suite runs on every `make test` | Slower test suite | ~90s overall; acceptable for the regression-protection value |

## Open coordination items

- **003-dependency-automation**: when Scala Steward proposes a BC
  version bump, CI's audit suite catches conformance regressions
  automatically. No new Steward config needed; the existing
  build + test gate handles it.
- **README.md**: roadmap update to insert 016, bump observability
  to 017 (done in this PR).
- **Future BC bump PR (if audit fails)**: a separate small PR
  driven by the audit's recommendation. Not part of 016 itself.

## What 016 explicitly does NOT do

- **Does NOT bump BC** — that's a downstream PR informed by the
  audit's findings.
- **Does NOT switch to bcfips or liboqs** — separate specs if /
  when needed.
- **Does NOT audit primitives outside ML-KEM-768 / ML-DSA-65** —
  current 012 / 013 scope only. SLH-DSA, Falcon, etc. would be
  separate audits.
- **Does NOT certify FIPS 140-3 module compliance** — that's a
  multi-month CMVP process beyond Siida's current scope.
