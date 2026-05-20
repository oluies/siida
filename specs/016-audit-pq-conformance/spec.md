# Feature Specification: Audit PQ Conformance (BC vs FIPS 203 / FIPS 204)

**Feature Branch**: `016-audit-pq-conformance`

**Created**: 2026-05-20

**Status**: Draft

**Input**: Spec 012 ships ML-KEM-768 via Bouncy Castle 1.78.1's
`KyberKEMGenerator`; spec 013 mandates ML-DSA-65 via BC's
`DilithiumSigner`. BC 1.78.1 released **April 2024**; FIPS 203 (ML-KEM)
and FIPS 204 (ML-DSA) were finalised **August 2024**. The version we
pinned predates the final standards. This spec verifies whether
BC 1.78.1's primitives match FIPS 203 / 204 byte-for-byte, and if
not, decides on remediation.

## Why this spec exists

Specs 012–015 claim "FIPS 203 ML-KEM-768" and "FIPS 204 ML-DSA-65" as
the cryptographic constructions. The Bouncy Castle library version
we pinned (`org.bouncycastle:bcprov-jdk18on:1.78.1`) implements the
**NIST Round-3 submission** of Kyber and Dilithium, which had small
post-submission tweaks during finalisation:

- **ML-KEM (Kyber)**: domain-separation byte ordering in `K-PKE`
  encrypt, the SHAKE-128 invocation in `XOF` calls, and a few
  hashing-input boundaries were adjusted between Round-3 and FIPS 203.
- **ML-DSA (Dilithium)**: the `ExpandMask` function was tightened
  and the rejection sampling for `s1` / `s2` had a small change.

These changes are MINOR (no security impact) but **do** affect
byte-for-byte output. A FIPS-validated counterparty implementing
exactly FIPS 203 would NOT interoperate with our ciphertexts if we
ship Round-3 Kyber. That breaks the cross-implementation
verification claim baked into specs 012 / 013.

The audit's deliverable: a pass/fail report against NIST CAVS / FIPS
ACVP test vectors, plus a documented remediation plan if any gap
exists.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - ML-KEM-768 conformance: BC output matches FIPS 203 reference vectors (Priority: P1)

A reviewer wants to confirm that the ML-KEM-768 ciphertexts our
mixnet emits are decryptable by any FIPS 203-conforming
implementation (and vice versa). The audit fetches NIST ACVP /
CAVS test vectors for ML-KEM-768, runs them through BC's
implementation, and compares outputs bit-for-bit.

**Why this priority**: P1 because if BC 1.78.1's Kyber768 deviates
from FIPS 203, the entire 012 wire format is non-interoperable
with the wider ecosystem — which undermines the whole rationale
for picking BSI-endorsed schemes (interop with other
European-cert-compliant deployments).

**Independent Test**: `./mill modules.crypto.test --testOnly siida.crypto.audit.MlKem768ConformanceSuite`
loads the NIST ACVP `ML-KEM-keyGen`, `ML-KEM-encapDecap`, and
`ML-KEM-decap` test vector files; runs each through BC's
`KyberKeyPairGenerator` / `KyberKEMGenerator` / `KyberKEMExtractor`;
asserts byte-for-byte equality. Pass → BC is FIPS 203 conformant
at 1.78.1. Fail → bump BC and retry, or escalate to a remediation
spec.

**Acceptance Scenarios**:

1. **Given** the NIST ACVP ML-KEM-768 keyGen vector set,
   **When** BC's keypair generator runs with the documented seed,
   **Then** the produced public key and secret key match the
   reference bytes.
2. **Given** the NIST ACVP encap/decap vector set,
   **When** BC encapsulates against the reference pk and decaps
   against the reference sk, **Then** the produced ciphertext
   and recovered shared secret both match the reference.

### User Story 2 - ML-DSA-65 conformance: BC output matches FIPS 204 reference vectors (Priority: P1)

Same as US1 but for the signature primitive: confirm BC's
`DilithiumSigner` matches FIPS 204 ML-DSA-65 byte-for-byte.

**Why this priority**: P1 because spec 013 promises ML-DSA-65;
spec 014's multi-signer config-chain entries are verifiable only
if the signatures conform. A FIPS-validated counterparty (e.g.,
a future PKG implementation built on a different library) would
reject non-conformant signatures and silently undermine the
governance chain.

**Independent Test**: `./mill modules.crypto.test --testOnly siida.crypto.audit.MlDsa65ConformanceSuite`
loads the NIST ACVP `ML-DSA-keyGen`, `ML-DSA-sigGen`, and
`ML-DSA-sigVer` test vector files; asserts byte-for-byte equality.

**Acceptance Scenarios**:

1. **Given** NIST ACVP ML-DSA-65 keyGen vectors, **When** BC
   generates a keypair with the same seed, **Then** the public
   and secret keys match.
2. **Given** ACVP sigGen vectors, **When** BC signs the reference
   message with the reference secret key, **Then** the signature
   matches byte-for-byte. (Note: ML-DSA is deterministic; same
   inputs → same output.)
3. **Given** ACVP sigVer vectors with valid (pk, msg, sig)
   tuples, **When** BC verifies, **Then** it accepts. With
   tampered tuples, BC rejects.

### User Story 3 - Document the conformance gap and remediation plan (Priority: P1)

The audit produces a written report at
`specs/016-audit-pq-conformance/notes-conformance.md` documenting:

- BC version under test
- Which ACVP vector sets pass (US1, US2)
- Which fail (if any) with byte-diff evidence
- Recommended remediation: bump BC to a specific later version
  that fixes the gap; or commit external FIPS-derived KATs to
  the test resources for cross-validation; or document that
  Siida's wire format diverges from FIPS 203 / 204 and amend the
  spec text accordingly.

**Why this priority**: P1 because the audit's value is only
realised when its result lands in the project's audit trail.
Running the suite without committing the report defeats the
exercise.

**Independent Test**: `notes-conformance.md` exists, has a header
section recording BC version + audit date + tester, and a table
of (vector set → pass/fail) with diff references for failures.

### Edge Cases

- **NIST vectors not yet published for a given parameter set**:
  if ACVP doesn't have ML-KEM-768 keyGen vectors at the time of
  audit (unlikely as of 2026-05-20 but possible if NIST is slow
  on the validation cadence), use the FIPS 203 standard's
  appendix examples or the Kyber reference implementation's
  Known Answer Tests (committed alongside the BC test vectors).
- **BC's API surface changes between 1.78 and a newer fix-up
  version**: if a bump to e.g. BC 1.79+ is required, our internal
  wrappers (`MlKem.scala`, `X25519.scala` in 012, and any added
  by 013) may need adjusting. The audit's remediation step
  documents this work as a follow-up code change.
- **bcfips-jdk18on alternative**: BC's FIPS 140-3 validated
  edition is a separate artefact (`org.bouncycastle:bcfips-jdk18on`).
  As of 2026-05 its PQ provider status is incomplete (no
  ML-KEM/ML-DSA yet). Note in the report; revisit when FIPS-mode
  becomes a procurement requirement.
- **liboqs / open-quantum-safe via JNI**: alternate PQ provider.
  Pure-Java not native-Java; would re-introduce 002's per-arch
  matrix complexity. Document as a fallback option in the
  remediation section, not the primary recommendation.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The audit MUST test BC's ML-KEM-768 implementation
  against the official NIST ACVP test vectors for FIPS 203
  ML-KEM, parameter set 3. Vectors live at
  `https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files`
  (or the canonical NIST source at the audit date); they are
  fetched once, committed to `modules/crypto/test/resources/acvp_ml_kem_768.json`,
  and the test suite consumes them.
- **FR-002**: The audit MUST test BC's ML-DSA-65 implementation
  against the official NIST ACVP test vectors for FIPS 204
  ML-DSA, parameter set 3. Vectors committed at
  `modules/crypto/test/resources/acvp_ml_dsa_65.json`.
- **FR-003**: Test suites MUST live under the package
  `siida.crypto.audit.*` so they're separable from per-primitive
  regression tests. Files: `MlKem768ConformanceSuite.scala`,
  `MlDsa65ConformanceSuite.scala`.
- **FR-004**: The audit suites MUST NOT be skipped from `make
  test` by default. They are part of the standard CI gate so
  conformance regressions are caught immediately if BC is bumped
  in a future Steward PR.
- **FR-005**: A written conformance report MUST land at
  `specs/016-audit-pq-conformance/notes-conformance.md` with the
  fields enumerated in US3.
- **FR-006**: If the audit fails for any vector set, the report
  MUST include the diff (first-N-byte comparison) of BC output
  vs reference output for at least one failing vector, plus a
  remediation recommendation.
- **FR-007**: The audit MUST also document the `bcfips-jdk18on`
  status: whether it supports ML-KEM-768 and ML-DSA-65 at the
  time of audit, with attribution to the BC release notes
  consulted.
- **FR-008**: If the audit passes, the report MUST link to the
  specific BC source-code commit (or release tag) that was tested
  so future auditors can re-verify against the same code.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: `MlKem768ConformanceSuite` returns either all-pass
  (BC 1.78.1 is FIPS 203 conformant) or specific-vector-failure
  with diff evidence in the report.
- **SC-002**: `MlDsa65ConformanceSuite` similarly returns
  all-pass or specific-vector-failure with diff evidence.
- **SC-003**: `notes-conformance.md` lands on `main` with the
  audit result and remediation plan. A reviewer reading it can
  answer in under 60 seconds: "Is BC at version X FIPS 203/204
  conformant for the parameter sets Siida uses?"
- **SC-004**: If the report says "bump BC", the follow-up PR
  doing the bump lands within 30 days. (Operational SC; not a
  test assertion.)
- **SC-005**: If the report says "Siida wire format diverges from
  FIPS 203", specs 012 / 013 / 014 / 015's text is amended to
  state the deviation explicitly, the algorithm-ID bytes (0x01,
  0x10, 0x20) are documented as "Siida hybrid using BC-flavoured
  Kyber/Dilithium" rather than literal FIPS 203/204, and a
  separate spec is reserved for the eventual FIPS-conformance
  cutover.

## Assumptions

- Constitution v2.0.0 holds; PQ migration is in flight.
- NIST ACVP test vectors are publicly available at the audit
  date. The ACVP repository
  (`github.com/usnistgov/ACVP-Server`) is the canonical source.
- BC 1.78.1 is the current pinned version; the audit may
  recommend bumping. Versions later than 1.78.1 (e.g., 1.79+)
  may have already incorporated the FIPS 203 / 204 finalisation
  tweaks; the audit determines whether a bump is necessary.
- The audit is **diagnostic**, not implementation. Any code
  change (BC bump, switch to `bcfips`, switch to liboqs) is a
  follow-up spec.
- Cryptographic non-conformance is not the same as cryptographic
  insecurity. Kyber Round-3 is still believed secure; it's just
  not byte-compatible with FIPS 203 implementations from
  validated providers. The audit's gap-finding informs interop,
  not security.
- "FIPS conformance" in this spec means **algorithm-level**
  byte-for-byte agreement with FIPS 203 / 204. It does **not**
  mean FIPS 140-3 module validation (that's `bcfips`'s
  territory). The two concepts are commonly conflated; this
  spec keeps them distinct.
