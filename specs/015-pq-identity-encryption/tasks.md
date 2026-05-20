---
description: "Task list for 015-pq-identity-encryption"
---

# Tasks: PQ Identity Encryption (PKG-Directory + HybridOnion)

**Input**: Design documents from `/specs/015-pq-identity-encryption/`

**Prerequisites**: spec.md, plan.md, research.md, contracts/{scala-api.md, wire-format.md, threat-model.md}. Depends on
spec 012 (HybridOnion — merged), spec 013 (PqSignature — merged),
and spec 014's `MultiSignedEntry` primitive.

**Spec 014 implementation is folded into this PR** because 015's
`Directory` requires `MultiSignedEntry.verify`. The full spec 014
remains a design-only document (consumed by spec 006); only the
verifier + assemble + serialise primitives ship here.

**Tests**: Round-trip, identity-not-found, cross-recipient
failure, tampered-entry rejection, wire-format size, uniform
alg-ID refusal.

---

## Phase 1: Setup

- [X] T001 No new dependencies needed — HybridOnion (012),
  PqSignature (013), and BC 1.84 (017) are all on main. _(done)_

---

## Phase 2: Foundational

- [X] T002 [P] Extend `modules/crypto/src/siida/crypto/api/Errors.scala`
  with three new enums:
  - `MultiSignedEntryError` (014 contract)
  - `VerifyResult` (014 verify-time outcome; sealed enum)
  - `IdentityEncError` (015 contract)
  _(done; all `derives CanEqual`)_
- [X] T003 [P] Write
  `modules/crypto/src/siida/crypto/api/MultiSignedEntry.scala` per
  014 contracts/scala-api.md: `assemble`, `verify`, `signedMessage`,
  `serialiseEntry`, `deserialiseEntry`, `FormatVersion = 0x01`.
  Wire format: 35 + n×3312 + |payload| bytes. **Documents the
  3312-vs-3296 tuple-size correction** — spec 014's wire-format
  contract assumed 3294-byte signatures (the design-doc value); the
  actual FIPS 204 ML-DSA-65 signature is 3309 bytes (per 013's
  implementation), so tuples are 2 + 3310 = 3312 bytes, not 3296.
  Refactored away non-local returns (Scala-3 deprecation). _(done)_

---

## Phase 3: User Story 1 — End-to-end encrypt-via-directory + decrypt (Priority: P1)

- [X] T004 [US1] Write
  `modules/crypto/src/siida/crypto/api/IdentityEncryption.scala`:
  - `IdentityCiphertext` opaque type
  - `encrypt(directory, identity, message, rng)` looking up via
    `Directory.lookup`, then `HybridOnion.encrypt`
  - `decrypt(secret, ct)` via `HybridOnion.decrypt` with uniform
    `DecapsulationFailed` per FR-006
  - `serialiseCiphertext` / `deserialiseCiphertext`
  - `AlgorithmID.IdentityEncryption_v1 = 0x20`
  - `Directory` trait + `Directory.inMemory` factory (verifies each
    entry's `MultiSignedEntry` on lookup against roster + threshold
    + DST)
  _(done; 8/8 IdentityEncryptionSuite tests pass)_
- [X] T005 [US1] Write
  `modules/crypto/test/src/IdentityEncryptionSuite.scala`: 8 tests
  covering end-to-end round-trip (one-identity directory),
  3-identity routing, IdentityNotFound on miss, cross-recipient
  decryption failure, tampered-entry rejection, serialise/
  deserialise round-trip, uniform alg-ID refusal, wire-format size
  (1138 + |payload|). _(done; all green)_

---

## Phase 4: User Story 2 — Directory entry signatures (Priority: P1)

- [X] T006 [US2] Verified by the tampered-entry test in
  `IdentityEncryptionSuite` (US1 phase) which proves the directory
  rejects entries whose `MultiSignedEntry` payload doesn't match
  its signed hash. The verifier is fully exercised in
  `MultiSignedEntrySuite` (11 tests) — happy-path, threshold
  violations, payload tamper, wrong DST, duplicate signer, OOB
  signer index, version + length rejection, wire-format size.
  _(done; 11/11 MultiSignedEntrySuite + tamper test pass)_

---

## Phase 5: User Story 3 — Privacy trade-off documented (Priority: P2)

- [X] T007 [US3] Threat-model trade-off is documented in
  `specs/015-pq-identity-encryption/contracts/threat-model.md`
  (already on main from the 013/014/015 design PR — merged via PR
  #32). Anonymous-routing mitigation is spec 005 (PKG) + spec 007
  (SDK) territory; out of 015's crypto-layer scope. _(done by
  prior design merge; no new work in this PR)_

---

## Phase N: Polish & Cross-Cutting Concerns

- [X] T008 Run `make check` end-to-end (headers + compile + test
  + ci-parity); expect green. _(green on darwin-arm64, EXIT=0,
  2026-05-20)_
- [X] T009 [P] Confirm test totals: was 75 crypto tests pre-015,
  now 94 (11 new MultiSignedEntrySuite + 8 new
  IdentityEncryptionSuite). _(confirmed)_

---

## Notes

- **Spec 014 implementation lives in this PR** by necessity:
  `IdentityEncryption.Directory.inMemory` requires
  `MultiSignedEntry.verify`. The full spec 014's scope (config-chain
  integration with spec 006) remains separate; only the primitive
  ships here.
- **Wire-format size correction**: spec 014's contract said
  "n × 3296" per tuple (assuming 3294-byte signatures); actual is
  "n × 3312" because FIPS 204 ML-DSA-65 signatures are 3309 bytes.
  The contract docs aren't updated in this PR; the implementation
  uses the corrected size and `MultiSignedEntry.TupleWireBytes`
  surfaces it for downstream callers.
- **Privacy regression noted but not mitigated in crypto**: the
  PKG learning per-query identities is the load-bearing trade-off
  of replacing Boneh-Franklin IBE. Mitigation (anonymous routing)
  is the SDK + PKG specs' concern (005 / 007).
- **No production-grade PQ-IBE**: confirmed during research R1
  of spec 015. Lattice-based, code-based, isogeny-based IBE all
  research-stage; PKG-directory is the pragmatic substitute.
- **Self-referential test fixtures only** — same as 002/012/013.
- The IdentityEncryption ciphertext carries TWO algorithm IDs at
  its head: `0x20` (identity-encryption v1) followed by the
  HybridOnion wire's `0x01` (hybrid v1). That's intentional —
  each layer has its own versioning.
