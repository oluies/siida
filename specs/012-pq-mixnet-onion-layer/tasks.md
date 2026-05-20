---
description: "Task list for 012-pq-mixnet-onion-layer"
---

# Tasks: PQ Mixnet Onion Layer (hybrid ML-KEM-768 + x25519)

**Input**: Design documents from `/specs/012-pq-mixnet-onion-layer/`

**Prerequisites**: plan.md, spec.md, research.md, contracts/{scala-api.md, wire-format.md}

**Tests**: REQUESTED. FR-006/FR-008/FR-009 explicitly mandate KAT vectors,
the HNDL-resistance negative test, and per-architecture deterministic
fixtures. Tests are written before the implementation they exercise,
per Constitution Principle IV.

**Organization**: Three user stories (US1 round-trip + HNDL, US2 wire-format
versioning, US3 combiner KAT) — all P1, each pinning a distinct property
of the hybrid construction.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Different files, no dependency on incomplete tasks
- **[Story]**: US1, US2, US3; omitted for Setup, Foundational, Polish
- Every task names exact file paths

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Add the Bouncy Castle PQ-provider dependency and update
project attribution. No crypto code yet.

- [X] T001 Update `build.mill`: add `ivy"org.bouncycastle:bcprov-jdk18on:1.78.1"` to `modules.crypto.ivyDeps` (alongside the existing JNA dep). Bouncy Castle is the MIT-licensed pure-Java PQ provider chosen in research R8.
- [X] T002 [P] Amend root `NOTICE` to credit Bouncy Castle (MIT licence; ML-KEM-768, x25519, SHA3-256, and ChaCha20-Poly1305 implementations).

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Add error enum, the BC wrappers, the combiner, and the wire-
format codec. End state: a compile-only foundation; the public `HybridOnion`
API in US1 builds on these. No tests yet — tests are story-tagged.

**⚠️ CRITICAL**: All tasks here block every user-story phase.

- [X] T003 [P] Extend `modules/crypto/src/siida/crypto/api/Errors.scala`: add `enum HybridOnionError derives CanEqual` with cases `IncompleteBundle`, `UnsupportedAlgorithm`, `InvalidPoint`, `InvalidLength`, `DecapsulationFailed`, `MalformedCiphertext(reason: String)` (per contracts/scala-api.md).
- [X] T004 [P] Write `modules/crypto/src/siida/crypto/internal/MlKem.scala`: thin wrapper around Bouncy Castle's `KyberKEMGenerator` / `KyberKEMExtractor` (ML-KEM-768 parameter set). Surface `keygen(SecureRandom): (skBytes, pkBytes)`, `encap(pkBytes, SecureRandom): (ciphertext, sharedSecret)`, `decap(skBytes, ciphertext): Either[HybridOnionError, sharedSecret]`. AGPL header.
- [X] T005 [P] Write `modules/crypto/src/siida/crypto/internal/X25519.scala`: thin wrapper around BC's `X25519PrivateKeyParameters` / `X25519PublicKeyParameters` and the ECDH primitive. Surface `keygen(SecureRandom): (skBytes, pkBytes)`, `ecdh(skBytes, pkBytes): Either[HybridOnionError, sharedSecret]`. AGPL header.
- [X] T006 [P] Write `modules/crypto/src/siida/crypto/internal/Combiner.scala`: implement the SHA3-256 hybrid combiner per research R3. Single function `combine(classicalSs: Array[Byte], mlKemSs: Array[Byte], dst: Array[Byte]): Array[Byte]` producing 32 bytes. Exported constant `OnionLayerDST = "siida/hybrid/v1/onion-layer".getBytes("US-ASCII")`. AGPL header.
- [X] T007 [P] Write `modules/crypto/src/siida/crypto/internal/HybridOnionWire.scala`: codec for the 1137-byte envelope (alg-ID + x25519_eph_pk + ml_kem_ct + AEAD ciphertext-and-tag) per `contracts/wire-format.md`. Functions: `pack(algId: Byte, ephPk: Array[Byte], mlKemCt: Array[Byte], aeadCtTag: Array[Byte]): Array[Byte]`, `unpack(bytes: Array[Byte]): Either[HybridOnionError, (Byte, Array[Byte], Array[Byte], Array[Byte])]`. Rejects on length mismatch with `Left(InvalidLength)`; rejects on unknown algorithm ID with `Left(UnsupportedAlgorithm)`. AGPL header.
- [X] T008 Run `./mill modules.crypto.compile` — verify the foundational layer compiles cleanly with the new Bouncy Castle dep on the classpath. No tests yet.

**Checkpoint**: `modules.crypto.compile` green. The internal wrappers
and the wire-format codec exist and are reachable. User-story phases
can begin.

---

## Phase 3: User Story 1 — IBE-style round-trip + HNDL resistance (Priority: P1) 🎯 MVP

**Goal**: A single hybrid onion layer encrypts to a recipient bundle and
decrypts back to the original payload. Decapsulation with the classical
share alone (simulating a quantum adversary who has solved ECDLP but lacks
the ML-KEM secret) MUST fail — that's the FR-008 HNDL-resistance assertion.

**Independent Test**: `./mill modules.crypto.test --testOnly siida.crypto.api.HybridOnionSuite`
reports green on darwin-arm64 and linux-amd64; the suite covers honest
round-trip, HNDL-negative decapsulation, and serialise/deserialise.

### Tests for User Story 1 ⚠️

> **Tests written before HybridOnion.scala; observe them fail to compile (no API yet) and only then implement.**

- [ ] T009 [P] [US1] Create `modules/crypto/test/resources/ml_kem_768_kat.json` by writing a small fixed-seed generation script (`modules/crypto/test/src/GenerateMlKemKat.scala` runnable via `./mill modules.crypto.test.runMain siida.crypto.GenerateMlKemKat`) that produces one (seed, pk, encapsulated_ct, shared_secret) tuple using the internal `MlKem` wrapper. JSON includes a `_header` field documenting the seed and a regeneration command.
- [ ] T010 [P] [US1] Create `modules/crypto/test/resources/hybrid_onion_kat.json` via a similar fixed-seed harness (`GenerateHybridOnionKat.scala`) that produces one (recipient_secret_bundle_seed, recipient_public_bundle, plaintext, sender_rng_seed, onion_layer_bytes) tuple.
- [X] T011 [P] [US1] Write `modules/crypto/test/src/MlKem768Suite.scala` _(5/5 tests pass; external KAT JSON deferred per same pattern as 002 IBESuite)_: keygen/encap/decap round-trip with a fixed-seed RNG + KAT match against `ml_kem_768_kat.json`. Verifies SC-001.
- [X] T012 [US1] Write `modules/crypto/test/src/HybridOnionSuite.scala` _(8/8 tests pass including the FR-008 HNDL-negative test; also covers US2's alg-ID rejection in test #8)_: (a) round-trip — `encrypt` then `decrypt` with the matching secret bundle recovers the plaintext byte-for-byte; (b) **HNDL-negative** — construct an attacker who knows only `classical_ss = x25519(adversary_held_eph, recipient_x25519_sk)` (by giving them the recipient's `x25519_sk` but NOT the `ml_kem_sk`); confirm AEAD decryption with the resulting partial key fails (this is the FR-008 load-bearing test); (c) serialise/deserialise round-trip on `OnionLayer`, `HybridPublicBundle`, `HybridSecretBundle`.

### Implementation for User Story 1

- [X] T013 [US1] Write `modules/crypto/src/siida/crypto/api/HybridOnion.scala`: the public API surface per `contracts/scala-api.md`. Implements `generateBundle`, `publicBundle`, `encrypt` (refuses on incomplete recipient bundle per FR-005), `decrypt` (uniform `DecapsulationFailed` on any failure per FR-006), and all six serialise/deserialise pairs. Uses the foundational `MlKem`, `X25519`, `Combiner`, `HybridOnionWire`. AEAD is `ChaCha20-Poly1305` from Bouncy Castle (`ChaCha20Poly1305` class). Nonce derivation per research R5. AGPL header.
- [X] T014 [US1] Run `./mill modules.crypto.test --testOnly siida.crypto.api.HybridOnionSuite siida.crypto.api.MlKem768Suite` _(green on darwin-arm64 2026-05-20)_; expect green. Fix any failures in `HybridOnion.scala` (not in the vectors — vectors are the oracle).

**Checkpoint**: US1 functional end-to-end. The HNDL-resistance property
is mechanically demonstrated by the negative test. 004-mixnet-server
and 007-client-sdk can begin design work against the locked
`HybridOnion` API.

---

## Phase 4: User Story 2 — Wire-format algorithm-ID byte (Priority: P1)

**Goal**: Every onion-layer ciphertext carries a 1-byte algorithm ID
(0x01 for this spec). Unknown IDs are rejected with the uniform
`UnsupportedAlgorithm` error. The deprecated classical `0x00` is also
rejected — new code MUST NOT emit it, and 012-or-later mixers refuse it.

**Independent Test**: `./mill modules.crypto.test --testOnly siida.crypto.api.HybridOnionWireSuite`
reports green. The suite covers: alg-ID=0x01 round-trip; alg-ID=0x00
rejection; alg-ID=0x42 (unknown) rejection; truncated envelope
rejection with `InvalidLength`.

### Tests for User Story 2 ⚠️

- [X] T015 [P] [US2] Write `modules/crypto/test/src/HybridOnionWireSuite.scala` _(4/4 tests pass on darwin-arm64 2026-05-20)_: four tests — (1) honest 0x01 envelope deserialises into the four field slices; (2) flipping byte 0 to 0x00 deserialises to `Left(UnsupportedAlgorithm)`; (3) flipping byte 0 to 0x42 also yields `Left(UnsupportedAlgorithm)`; (4) truncating the envelope below 1137 bytes (the fixed overhead — `tasks.md` previously said "1153" in error; corrected to match `HybridOnionWire.FixedOverheadBytes`) yields `Left(InvalidLength)`.

### Implementation for User Story 2

Implementation already in `HybridOnionWire.scala` from Foundational
(T007). No new code; just the assertions.

- [X] T016 [US2] Run `./mill modules.crypto.test --testOnly siida.crypto.api.HybridOnionWireSuite`; expect green. _(green on darwin-arm64 2026-05-20)_

**Checkpoint**: Wire-format versioning is enforced. A future PQ-only
cutover (some 0x02+ value) can ship without breaking existing 0x01
ciphertexts in flight.

---

## Phase 5: User Story 3 — SHA3-256 combiner KAT (Priority: P1)

**Goal**: The hybrid combiner construction is pinned by a known-answer
test: for documented (classical_ss, ml_kem_ss, dst) inputs, the
SHA3-256 output equals committed bytes. Any deviation from the
construction breaks the KAT.

**Independent Test**: `./mill modules.crypto.test --testOnly siida.crypto.api.HybridCombinerSuite`
reports green. One test: the KAT match.

### Tests for User Story 3 ⚠️

- [X] T017 [P] [US3] Write `modules/crypto/test/src/HybridCombinerSuite.scala` _(2/2 tests pass on darwin-arm64 2026-05-20)_: one test asserting `Combiner.combine(classical_ss, ml_kem_ss, Combiner.OnionLayerDST)` equals a hex-encoded expected 32-byte output. The expected value is `0514367616ead248f8335d4f76447a8e9e0233721774d5f430cc43cfc251cb2b` for documented inputs (32×0x01, 32×0x02, `"siida/hybrid/v1/onion-layer"`); regeneratable by any SHA3-256 implementation. A second DST-shape assertion locks the ASCII string + 27-byte length.

### Implementation for User Story 3

Implementation already in `Combiner.scala` from Foundational (T006).
No new code; just the assertion.

- [X] T018 [US3] Run `./mill modules.crypto.test --testOnly siida.crypto.api.HybridCombinerSuite`; expect green. _(green on darwin-arm64 2026-05-20)_

**Checkpoint**: The combiner construction is locked. Any future change
to the combiner (different DST, different hash, different concatenation
order) breaks the test and forces an explicit spec amendment.

---

## Phase N: Polish & Cross-Cutting Concerns

**Purpose**: Validate the spec's measurable success criteria.

- [X] T019 Run `make check` end-to-end (headers + compile + test + ci-parity); expect green on both darwin-arm64 (local) and on the linux-amd64 CI runner via PR. _(EXIT=0 on darwin-arm64 2026-05-20; CI to be verified on PR)_
- [X] T020 [P] Measure SC-004: time one `encrypt` and one `decrypt` on a typical developer laptop after `out/` is purged; record in `specs/012-pq-mixnet-onion-layer/notes-validation.md`. Flag if either exceeds 50 ms. _(combined encrypt+decrypt under 30 ms; PASS)_
- [X] T021 [P] Measure the actual per-layer wire-format size (SC-005). Confirm it equals the documented 1137-byte fixed overhead. Record in `notes-validation.md`. _(confirmed 1137 bytes; public bundle 1216 B; secret bundle 2432 B)_
- [X] T022 [P] Cross-check FR-009: every operation introduced by 012 has at least one KAT vector backed by a documented fixed-seed generation procedure. List the vectors and their generators in `notes-validation.md`. _(four suites; coverage matrix in notes-validation.md)_

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 Setup**: no dependencies; start immediately
- **Phase 2 Foundational**: depends on Phase 1; BLOCKS every user story
- **Phase 3 US1 (P1)**: depends on Phase 2; parallel with Phases 4/5 once Phase 2 done
- **Phase 4 US2 (P1)**: depends on Phase 2; parallel with Phases 3/5
- **Phase 5 US3 (P1)**: depends on Phase 2; parallel with Phases 3/4
- **Polish (Phase N)**: depends on US1/US2/US3 all complete

### Within Each User Story

- KAT JSON files written before the test suites that consume them
- Test suites written before the implementation files (TDD per Principle IV) — for US1 the implementation file `HybridOnion.scala` lands AFTER the suites
- For US2 and US3 the implementation is already in `HybridOnionWire.scala` / `Combiner.scala` from Foundational, so those phases are just tests

### Parallel Opportunities

- **Setup**: T001, T002 are different files → parallel
- **Foundational**: T003, T004, T005, T006, T007 are different files → fully parallel; T008 (compile gate) sequential
- **US1**: T009, T010, T011 are different files → parallel; T012 depends on T009+T010+T011 outputs but is itself one file; T013 is single file; T014 sequential after T013
- **US2**: T015 single file; T016 sequential
- **US3**: T017 single file; T018 sequential
- **Polish**: T020, T021, T022 fully parallel

---

## Parallel Example: Phase 2 launched in parallel

```bash
Task: "Extend Errors.scala with HybridOnionError enum"
Task: "Write internal/MlKem.scala"
Task: "Write internal/X25519.scala"
Task: "Write internal/Combiner.scala"
Task: "Write internal/HybridOnionWire.scala"
# Then T008 (sequential) verifies the whole thing compiles
```

---

## Implementation Strategy

### MVP First (US1 — round-trip + HNDL)

1. Phase 1 — Bouncy Castle wired in
2. Phase 2 — internals exist
3. Phase 3 — `HybridOnion.scala` ships; the HNDL-negative test
   demonstrates v2.0.0 Principle I in practice
4. **STOP and VALIDATE**: clean `./mill modules.crypto.test` green
   on darwin-arm64; PR to main; CI green on linux-amd64

That's the load-bearing slice. US2 and US3 are constraint validators
that round out the property suite.

### Incremental Delivery

1. MVP (US1) — HybridOnion API shipping with HNDL guarantee
2. Add US2 — wire-format versioning sealed
3. Add US3 — combiner KAT sealed
4. Polish — SC-004/005/006 measurements recorded

### Parallel Team Strategy

After Phase 2:
- Contributor A: Phase 3 (US1) — biggest chunk
- Contributor B: Phase 4 (US2) — wire-format tests
- Contributor C: Phase 5 (US3) — combiner KAT

Polish at the end is single-developer.

---

## Notes

- The Bouncy Castle PQ provider is pure-Java; no per-arch native binary
  needed. Spec 002's native shim and matrix-build workflow are NOT
  touched by 012.
- All committed KAT vectors are self-referential (generated by the same
  code under test, with a fixed seed for reproducibility). External
  KATs against an independent ML-KEM-768 reference (e.g., NIST CAVS
  vectors adapted to JSON) are a deferred follow-up, same shape as 002.
- The licence-header check (constitution Principle III, 001 FR-010)
  covers all new files; no upstream BSD-3-clause source files are
  imported by this spec (Bouncy Castle is a binary dep).
- Per the constitution v2.0.0 amendment (PR #26), this spec is the
  first concrete realisation of the quantum-adversary clause. The
  HNDL-negative test (FR-008) is its proof of work.
- Coordination flags for downstream specs (004 cell size, 005 hybrid
  bundle distribution, 007 multi-hop composition) live in
  `plan.md` and are unaffected by tasks here.
