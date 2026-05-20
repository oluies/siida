---
description: "Task list for 017-bc-version-bump"
---

# Tasks: Bouncy Castle Version Bump

**Input**: Design documents from `/specs/017-bc-version-bump/`

**Prerequisites**: spec.md, plan.md, research.md, AND spec 016's
audit suites (PR #35) on `main`.

**Tests**: The 016 audit suites are the verification.

**Outcome**: **Scenario A** — full FIPS 203 / 204 conformance.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: The bump

- [X] T001 [US1] Update `build.mill`: change `bcprov-jdk18on:1.78.1`
  to `bcprov-jdk18on:1.84`. Verify the new artefact resolves from
  Maven Central and the `Versions.licence` allowlist still
  matches (BC is MIT through 1.84, unchanged). _(done; mill
  resolves cleanly)_

---

## Phase 2: Source updates (BC API moves)

BC 1.84 reorganised the public PQ API. The classes previously at
`org.bouncycastle.pqc.crypto.crystals.{kyber,dilithium}.*` were
removed (the FIPS-named `pqc.crypto.{mlkem,mldsa}.*` shims also
exist but are deprecated). The fully-supported locations are
under `org.bouncycastle.crypto.{generators,kems,signers,params}`.

- [X] T002 [US1] Update `modules/crypto/src/siida/crypto/internal/MlKem.scala`:
  switch imports from `pqc.crypto.crystals.kyber.*` to
  `crypto.{generators.MLKEMKeyPairGenerator, kems.MLKEMGenerator,
  kems.MLKEMExtractor, params.MLKEM*}`. Rename
  `KyberParameters.kyber768` → `MLKEMParameters.ml_kem_768`.
  Wire sizes unchanged. _(done; compile clean)_
- [X] T003 [US1] Update `modules/crypto/src/siida/crypto/api/HybridOnion.scala`
  line 238 area (the `mlKemPkFromSk` helper): import
  `MLKEMParameters` / `MLKEMPrivateKeyParameters` from
  `crypto.params`. _(done; compile clean)_

---

## Phase 3: Audit re-baseline

- [X] T004 [US1] Update `modules/crypto/test/src/siida/crypto/audit/MlKem768ConformanceSuite.scala`:
  - Switch imports to the non-deprecated BC 1.84 paths
  - Update baseline constants:
    - `baselineKeyGenPass: 0 → 25`
    - `baselineEncapPass: 25 → 25` (unchanged)
    - `baselineDecapPass: 25 → 25` (unchanged)
  _(done; 3/3 tests green)_
- [X] T005 [US1] Update `modules/crypto/test/src/siida/crypto/audit/MlDsa65ConformanceSuite.scala`:
  - Switch imports to the non-deprecated BC 1.84 paths
  - Add `ParametersWithContext` import (new in BC 1.84)
  - Rewrite the sigGen test to use the streaming API
    (`signer.init(true, ParametersWithContext(priv, ctx))`;
    `signer.update(msg, 0, msg.length)`; `signer.generateSignature()`)
  - Update baseline constants:
    - `baselineKeyGenPass: 0 → 25`
    - `baselineSigGenPass: 0 → 15`
  _(done; 2/2 tests green; ctx parameter now correctly conveyed)_

---

## Phase 4: Documentation

- [X] T006 [US2] Write
  `specs/017-bc-version-bump/notes-bump.md`: the bump record
  including the before/after audit table, the BC API class moves,
  the static-field renames, the ML-DSA streaming-API change, and
  the operational consequences. _(done; ~6 KB)_

---

## Phase N: Polish & Cross-Cutting

- [X] T007 Run `make check` end-to-end (headers + compile + test
  + ci-parity); expect green. _(green on darwin-arm64, EXIT=0,
  2026-05-20)_
- [X] T008 [P] Verify total test count is unchanged at 60 crypto
  tests — bump didn't accidentally drop coverage. _(confirmed:
  49 prior + 5 audit + 6 HybridOnion/Wire/Combiner = 60)_

---

## Dependencies

- Phase 1 blocks 2 / 3 / 4 (audit suites and source updates need
  the bumped BC on the classpath to verify their changes).
- Phase 2 and Phase 3 are interleaved during compile-failure
  iteration (the compiler tells us exactly what classes moved).
- Phase 4 + Polish run after Phases 2 and 3 pass.

## Notes

- **Scenario A applies.** BC 1.84 is fully FIPS 203 / 204
  conformant for the parameter sets Siida uses. No US2
  ("document and decide a residual gap") action needed; no
  spec 018-ml-dsa-ctx-wrapper or 018-switch-to-liboqs required.
- The BC API move (from `pqc.crypto.crystals.*` to
  `crypto.{generators,kems,signers,params}.*`) was anticipated
  in research R3 as a possibility; it's absorbed in-PR per
  FR-002's "minimal source updates" allowance. Total source
  delta: ~30 lines across 4 files.
- The audit suite is now genuinely a "guardrail" rather than a
  "documented baseline of brokenness": if a future Steward bump
  silently introduces a regression, the audit will catch it.
- This PR does NOT touch 012 / 013 / 015 spec text — their
  FIPS-conformance claims now happen to be true post-017, but
  the spec text was already correct (FIPS 203 / 204 with BC as
  the provider). Updating spec wording isn't necessary.
