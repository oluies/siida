---
description: "Task list for 013-pq-bls-replacement"
---

# Tasks: PQ BLS Replacement (ML-DSA-65)

**Input**: Design documents from `/specs/013-pq-bls-replacement/`

**Prerequisites**: spec.md, plan.md, research.md, contracts/scala-api.md.
Spec 017 (BC 1.78.1 → 1.84) merged on main; 013 implements against
the BC 1.84 ML-DSA API (FIPS-conformant, includes `ParametersWithContext`
for ctx support).

**Tests**: Sign/verify round-trip, forgery negatives, batch verify,
serialise/deserialise, wire-format sizes, uniform alg-ID refusal.

**Organization**: Three user stories (US1 single sig, US2 absence of
aggregate, US3 batch verify) — all P1/P2.

---

## Phase 1: Setup

- [X] T001 Verify BC ML-DSA-65 access via the new
  `org.bouncycastle.crypto.{generators,kems,signers,params}` paths
  introduced in spec 017. No new dependency needed; BC 1.84 already
  in `modules.crypto.ivyDeps`. _(done)_

---

## Phase 2: Foundational

- [X] T002 [P] Extend
  `modules/crypto/src/siida/crypto/api/Errors.scala`: add
  `enum PqSignatureError derives CanEqual` with cases
  `UnsupportedAlgorithm`, `InvalidLength`, `MalformedKey`,
  `MalformedSignature`. AGPL header inherited. _(done)_
- [X] T003 [P] Write
  `modules/crypto/src/siida/crypto/internal/MlDsa.scala`: thin BC
  wrapper providing `keygen(rng)`, `sign(sk, msg)`, `verify(pk, msg,
  sig)`. Uses `MLDSAParameters.ml_dsa_65`, `MLDSAKeyPairGenerator`,
  `MLDSASigner` with the streaming API (`init → update → generateSignature`).
  Signing is deterministic (FIPS 204 rnd=0^32 path). Wire sizes:
  pk=1952, sk=4032, sig=3309 (FIPS 204 Table 1; the design doc's
  3293 was incorrect). AGPL header. _(done)_

---

## Phase 3: User Story 1 — Single PQ signature (Priority: P1)

- [X] T004 [US1] Write `modules/crypto/src/siida/crypto/api/PqSignature.scala`:
  the public API per `contracts/scala-api.md`. Opaque types
  `PqPrivateKey`, `PqPublicKey`, `Signature` live INSIDE the object
  (same Scala-3 opaque-type lesson as 012's HybridOnion). Functions:
  `generateKeyPair`, `publicKey`, `sign`, `verify`, `batchVerify`,
  six serialise/deserialise pairs, `AlgorithmID` constants
  (0x10 active; 0x11/0x12/0x13 reserved). Wire formats include 1-byte
  alg-ID prefix (1953/4033/3310 bytes). AGPL header. _(done; 15/15
  PqSignatureSuite tests pass)_
- [X] T005 [US1] Write `modules/crypto/test/src/PqSignatureSuite.scala`
  with 15 tests covering sign/verify round-trip, forgery negatives
  (wrong key + tampered message), determinism, batch verify
  (positive + forged + empty), wire-format sizes, serialise/
  deserialise round-trips, alg-ID uniform refusal (FR-013),
  `publicKey(sk)` recovery. AGPL header. _(done; 15/15 green on
  darwin-arm64 2026-05-20)_

---

## Phase 4: User Story 2 — Aggregation removed; @deprecated discipline (Priority: P1)

- [X] T006 [US2] Add `@deprecated(..., "v2.0.0")` annotation to
  `siida.crypto.api.BLS` object in `BLS.scala`. Reason text
  references constitution v2.0.0 Principle I (BN254 quantum
  vulnerability) and points callers at `PqSignature`. _(done)_
- [X] T007 [US2] Suppress the deprecation cascade in `BLSSuite`
  with `@scala.annotation.nowarn("cat=deprecation")` on the suite
  class. The suite continues to regression-test classical BLS
  through the migration window; the warnings are expected, not
  noise. _(done; BLSSuite 13/13 still passes)_
- [X] T008 [US2] Verify the `PqSignature` API contract has NO
  `aggregate` method — confirmed by inspection of
  `siida.crypto.api.PqSignature` and `contracts/scala-api.md`. The
  absence is the load-bearing semantic change of this spec
  (SC-006). _(done)_

---

## Phase 5: User Story 3 — Batch verification (Priority: P2)

- [X] T009 [US3] Implement `PqSignature.batchVerify(tuples)`:
  sequential `verify` loop with empty-input → false (FR-006) and
  uniform refusal (FR-013). _(done; included in T004)_
  
  **Note**: BC 1.84's public API doesn't expose the lattice
  primitives needed for the Pino-Vidaud randomised-coefficient
  construction (research R3). 013 ships the sequential
  implementation; the API contract is satisfied (correct boolean
  return) but the SC-003 "≥1.5× speedup" target is not met
  empirically. Documented in `PqSignature.scala` docstring as a
  follow-up opportunity when BC exposes the primitives or via a
  JNI to a library that does.

---

## Phase N: Polish & Cross-Cutting Concerns

- [X] T010 Run `make check` end-to-end (headers + compile + test
  + ci-parity); expect green. _(green on darwin-arm64, EXIT=0,
  2026-05-20)_
- [X] T011 [P] Confirm test totals: was 60 crypto tests pre-013,
  now 75 (15 new PqSignatureSuite tests added; BLSSuite still at
  13). _(confirmed: 75 crypto tests, all green)_

---

## Notes

- **FIPS 204 ML-DSA-65 signature size is 3309 bytes** (per FIPS 204
  Table 1), not 3293 as stated in spec / contracts. The contract
  text was incorrect; the implementation uses the actual FIPS-spec
  size. Wire format with alg-ID prefix = 3310 bytes.
- **Aggregation absence is the load-bearing semantic change.**
  Callers needing many-signer attestations use batch verification
  (US3) or the 014-config-chain-redesign approach.
- **Spec 014 (config-chain redesign)** consumes `MultiSignedEntry`
  built on per-signer ML-DSA-65 signatures + threshold count. The
  PqSignature API is the foundation; 014's implementation is
  separate.
- **Hybrid signatures explicitly rejected** per research R4 and
  BSI/ENISA guidance. No `verifyHybrid` or dual-sig-acceptance
  path in 013's API.
- The classical `BLS` object stays compilable via `@deprecated`
  for the duration of the migration. Hard removal happens after
  014's config-chain redesign lands and any other BLS consumer
  cuts over.
- Self-referential test fixtures only — external NIST CAVS
  vectors deferred to a future spec, same as 002/012. The 016
  audit's NIST ACVP vectors cover ML-DSA-65 conformance from a
  different angle.
