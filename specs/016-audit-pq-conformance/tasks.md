---
description: "Task list for 016-audit-pq-conformance"
---

# Tasks: PQ Conformance Audit (BC vs FIPS 203 / FIPS 204)

**Input**: Design documents from `/specs/016-audit-pq-conformance/`

**Prerequisites**: plan.md, spec.md, research.md

**Tests**: This spec IS the test layer. Production code is not changed.

**Organization**: Three user stories — US1 ML-KEM-768 conformance,
US2 ML-DSA-65 conformance, US3 written report. All P1.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup (Shared Infrastructure)

- [X] T001 [P] Fetch NIST ACVP vector files (`internalProjection.json`)
  from `github.com/usnistgov/ACVP-Server/gen-val/json-files/` for
  `ML-KEM-keyGen-FIPS203`, `ML-KEM-encapDecap-FIPS203`,
  `ML-DSA-keyGen-FIPS204`, `ML-DSA-sigGen-FIPS204`. Down-select to
  parameter set 3 (ML-KEM-768, ML-DSA-65) — for sigGen, down-select
  to `tgId=3` (deterministic, pure, external-mu=false). Commit
  under `modules/crypto/test/resources/acvp/`. Total ~1.1 MB across
  90 test cases. _(done; sizes: keygen 184 KB, encapdecap 239 KB,
  dsa-keygen 302 KB, dsa-siggen 413 KB)_

---

## Phase 2: Foundational (Blocking Prerequisites)

- [X] T002 [P] Write `modules/crypto/test/src/siida/crypto/audit/AcvpJson.scala`:
  minimal hand-rolled JSON parser tailored to the ACVP schema
  (objects / arrays / strings / integers / bool / null). Avoids
  pulling in a JSON dependency for one-off audit-only use. AGPL header.
- [X] T003 [P] Write `modules/crypto/test/src/siida/crypto/audit/AcvpVectorReader.scala`:
  typed loader over `JsonValue`, including hex-decode / hex-encode
  helpers and a `hexShort` for log-friendly truncation. AGPL header.
- [X] T004 [P] Write `modules/crypto/test/src/siida/crypto/audit/DeterministicSecureRandom.scala`:
  SecureRandom subclass that returns bytes from a pre-loaded buffer,
  for injecting ACVP fixed seeds into BC's
  `KyberKeyPairGenerator` / `KyberKEMGenerator` /
  `DilithiumKeyPairGenerator` / `DilithiumSigner`. Throws if
  callers pull more bytes than the buffer holds (surfaces
  unexpected randomness use). AGPL header.

---

## Phase 3: User Story 1 — ML-KEM-768 conformance (Priority: P1)

**Goal**: Run NIST ACVP ML-KEM-768 vectors through BC and assert
the observed pass/fail counts match the documented baseline.

**Independent Test**: `./mill modules.crypto.test --testOnly siida.crypto.audit.MlKem768ConformanceSuite`
green; 3 tests covering keyGen, encap, decap.

- [X] T005 [US1] Write `modules/crypto/test/src/siida/crypto/audit/MlKem768ConformanceSuite.scala`:
  three tests (keyGen, encap, decap) loading the ACVP JSON files,
  injecting seeds via `DeterministicSecureRandom`, comparing
  byte-for-byte to expected values, and asserting observed
  pass-counts match the documented baseline. Baseline for BC 1.78.1:
  keyGen 0/25, encap 25/25, decap 25/25 — the unusual finding that
  BC's K-PKE.Encrypt/Decrypt match FIPS 203 but K-PKE.KeyGen does
  not. _(3 tests pass on darwin-arm64 2026-05-20)_

---

## Phase 4: User Story 2 — ML-DSA-65 conformance (Priority: P1)

**Goal**: Run NIST ACVP ML-DSA-65 vectors through BC and assert the
observed pass/fail counts match the documented baseline.

**Independent Test**: `./mill modules.crypto.test --testOnly siida.crypto.audit.MlDsa65ConformanceSuite`
green; 2 tests covering keyGen and sigGen tg 3.

- [X] T006 [US2] Write `modules/crypto/test/src/siida/crypto/audit/MlDsa65ConformanceSuite.scala`:
  two tests (keyGen, sigGen tg 3 deterministic-pure) loading the
  ACVP JSON files, comparing byte-for-byte to expected, asserting
  observed pass-counts match the documented baseline. Baseline for
  BC 1.78.1: keyGen 0/25, sigGen 0/15 — BC ships Round 3, lacks
  ctx parameter, and has other internal Round-3-vs-FIPS-204
  divergences. _(2 tests pass on darwin-arm64 2026-05-20)_

---

## Phase 5: User Story 3 — Written conformance report (Priority: P1)

**Goal**: Document the audit findings, the BC version timeline, the
unusual ML-KEM nuance (keyGen fails but encap/decap pass), the
ML-DSA gaps (ctx + Round 3), the bcfips status, the
remediation recommendation, and what the audit does NOT cover.

- [X] T007 [US3] Write `specs/016-audit-pq-conformance/notes-conformance.md`
  with the structure above. Cite specific findings (0/25 keyGen,
  25/25 encap, 25/25 decap, 0/25 ML-DSA keyGen, 0/15 ML-DSA sigGen)
  and recommend a focused follow-up spec (`017-bc-version-bump`)
  rather than a bigger architectural switch. _(done; ~5 KB)_

---

## Phase N: Polish & Cross-Cutting Concerns

- [X] T008 Run `make check` end-to-end (headers + compile + test +
  ci-parity); expect green. _(green on darwin-arm64 2026-05-20)_
- [X] T009 [P] Verify the audit suites are part of the default `make
  test` run (FR-004) — no opt-in flag or environment variable
  needed. _(confirmed; the suites run as part of `modules.crypto.test`
  in standard test discovery)_

---

## Dependencies & Execution Order

- Phase 1 vector fetch must complete before Phase 2/3/4 (suites
  need vector files to load)
- Phase 2 foundational utilities (JSON parser, vector reader, det.
  SecureRandom) block US1 / US2 / US3
- US1, US2, US3 can run in parallel after Phase 2
- Polish (Phase N) runs after all stories

## Notes

- The audit is a permanent guardrail, not a one-time check. Future
  Scala Steward BC bumps trigger the suite via `make test`; any
  result change (better or worse) breaks the baseline and forces
  a human review + report update.
- The "baseline-snapshot" pattern (assert observed == documented)
  is the load-bearing design decision. It satisfies FR-004
  (mandatory in `make test`) without breaking the build, while
  still catching every conformance change.
- No production-code changes by this spec. The `siida.crypto.audit`
  package contains only test code under `modules/crypto/test/src/`.
- Resource files (~1.1 MB of ACVP JSON) are CC0-licensed
  (NIST public-domain), licence-compatible per constitution III.
