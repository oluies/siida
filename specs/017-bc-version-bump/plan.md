# Implementation Plan: Bouncy Castle Version Bump

**Branch**: `017-bc-version-bump` | **Date**: 2026-05-20 | **Spec**: [spec.md](./spec.md)

## Summary

Bump `org.bouncycastle:bcprov-jdk18on` from 1.78.1 to 1.84
(latest stable, May 2026), re-run the 016 audit, update baseline
constants and the conformance report. Small, mechanical, audited
by the 016 suite as the verification step.

If audit baselines flip to "all pass" — gap closed end-to-end.
If they partially close, the spec documents what remains and
recommends the next step (e.g., a small ctx wrapper or a
provider switch — both downstream specs).

## Technical Context

**Language / Version**: Scala 3.6.4 / JDK 21 LTS (inherited).

**Primary Dependency Change**:
- `org.bouncycastle:bcprov-jdk18on:1.78.1` → `1.84`

**Storage**: No new resources. Existing ACVP JSON vectors under
`modules/crypto/test/resources/acvp/` are reused verbatim.

**Testing**: The 016 audit suites
(`siida.crypto.audit.MlKem768ConformanceSuite`,
`siida.crypto.audit.MlDsa65ConformanceSuite`) are the
verification. Baseline constants in those files get updated to
reflect BC 1.84's behaviour.

**Target Platform**: Linux/amd64, Linux/arm64, Darwin/arm64. No
new platform concerns; BC is pure-Java.

**Project Type**: Dependency bump + test-baseline update. No new
production code.

**Performance Goals**: Audit suite still completes in < 1 second.

**Constraints**:
- Single-version literal change in `build.mill`.
- Audit suite stays mandatory in `make test`.
- Constitution Principle III (licence) re-verified.

**Scale / Scope**:
- 1 file edit in `build.mill` (version literal)
- 2 file edits for baseline updates (MlKem / MlDsa suites)
- 1 file edit for the conformance report
- 1 file edit for `README.md` roadmap

## Constitution Check

### Principle I — Metadata Privacy is Non-Negotiable (v2.0.0)
**Pass.** BC bump does not affect any metadata-touching code path.

### Principle II — Spec-Driven, Numbered Feature Workflow
**Pass.** 017 is the next number; no skips.

### Principle III — Licence Integrity
**Pass.** BC remains MIT (Bouncy Castle Project) through 1.84.
`NOTICE` re-verified as correct.

### Principle IV — Test-First with Deterministic Rounds
**Pass.** The 016 audit is the test; written before the bump per
the spec workflow.

### Principle V — JVM-Native Mixnet Core
**Pass.** BC is pure-Java; no JNI; no per-arch matrix.

### Re-check after Phase 1
**PASS.** No new violations.

## Project Structure

### Documentation (this feature)

```text
specs/017-bc-version-bump/
├── plan.md
├── spec.md
├── research.md
├── checklists/
│   └── requirements.md
├── tasks.md             # (Phase 2 output)
└── notes-bump.md        # written audit-after-bump record
```

### Source Code

```text
build.mill                                                — version literal
modules/crypto/test/src/siida/crypto/audit/
  MlKem768ConformanceSuite.scala                          — baseline constants
  MlDsa65ConformanceSuite.scala                           — baseline constants
specs/016-audit-pq-conformance/notes-conformance.md       — appended with bump result
specs/017-bc-version-bump/notes-bump.md                   — NEW; the bump report
README.md                                                 — roadmap row insert
```

No new files outside docs / spec; no new public API surface.

**Structure Decision**: keep all audit-test code where 016 left
it. The bump's only code-side surface is the build literal and
two baseline-constant updates.

## Complexity Tracking

| Item | Note | Why not a violation |
|---|---|---|
| Single PR carries spec + plan + research + impl | Larger than typical "design-only" PR | The bump is so mechanical (one version literal) that splitting design + impl across two PRs adds overhead without value. The 016 audit is the binding verification step. |
| Skipping minor versions (1.78.1 → 1.84) | Some teams prefer one-minor-at-a-time | The audit catches regressions either way; the bigger jump consolidates work and brings Steward to the head of the release line. |

## Open coordination items

- **003-dependency-automation**: after 017 lands, Steward's next
  proposal will be ~1.85 (when released). The 016 audit catches
  any conformance regression automatically; no Steward-config
  changes needed.
- **013-pq-bls-replacement** (pending impl): the bump unblocks
  013's "FIPS 204 ML-DSA-65 conformance" claim — if 017's audit
  ends in scenario A (all-pass), 013 can implement against a
  conformant primitive.
- **015-pq-identity-encryption** (pending impl): same — 015's
  protocol design rebuilds against HybridOnion (012). If 017
  closes 012's gap, 015 inherits that improvement.

## What 017 explicitly does NOT do

- Does NOT switch providers.
- Does NOT touch 012 / 013 / 015 spec text (unless audit results
  require — in which case minimal amendments are in-scope).
- Does NOT add new audit primitives (e.g., SLH-DSA, Falcon).
- Does NOT certify FIPS 140-3 module validation.
