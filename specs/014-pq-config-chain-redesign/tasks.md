---
description: "Task list for 014-pq-config-chain-redesign (crypto primitive only)"
---

# Tasks: PQ Config-Chain Redesign — MultiSignedEntry primitive

**Input**: Design documents from `/specs/014-pq-config-chain-redesign/`

**Prerequisites**: spec.md, plan.md, research.md, contracts/{scala-api.md, wire-format.md}. Depends on spec 013
(PqSignature — merged).

**Scope of THIS task list**: only the cryptographic primitive
(`siida.crypto.api.MultiSignedEntry`). The full integration into a
config-chain implementation is spec 006's territory; 014's primitive
is implemented here as part of 015's PR because spec 015
(`Directory.inMemory`) requires `MultiSignedEntry.verify` at lookup
time.

**Tests**: Threshold validation, duplicate-signer rejection,
out-of-range signer index, payload-tamper rejection, wrong-DST
rejection, serialisation, version-byte refusal.

---

## Phase 1: Setup

- [X] T001 No new dependencies — PqSignature (013) provides the
  per-signer scheme; SHA3-256 from JDK. _(done)_

---

## Phase 2: Implementation

- [X] T002 Extend `modules/crypto/src/siida/crypto/api/Errors.scala`
  with `MultiSignedEntryError` and `VerifyResult` enums per 014
  contracts/scala-api.md. Both derive `CanEqual`. _(done as part
  of 015's PR; folded since 015's `Directory.inMemory` uses
  `VerifyResult.Valid` directly)_
- [X] T003 Write `modules/crypto/src/siida/crypto/api/MultiSignedEntry.scala`:
  - `Entry` opaque type
  - `FormatVersion = 0x01`
  - `signedMessage(payload, dst)` helper
  - `assemble(payload, signatures)` constructor with duplicate-
    signer rejection at build time
  - `verify(roster, threshold, dst, entry)` returning `VerifyResult`
  - `serialiseEntry` / `deserialiseEntry`
  - `TupleWireBytes` surface constant (= 3312, the actual tuple
    size accounting for FIPS 204's 3309-byte signatures, not the
    contract's 3296)
  _(done; 11/11 MultiSignedEntrySuite tests pass)_

---

## Phase 3: Test

- [X] T004 Write `modules/crypto/test/src/MultiSignedEntrySuite.scala`:
  11 tests covering happy-path 3-of-5 / 5-of-5, threshold violation
  (2-of-5 below threshold 3), payload tamper, wrong DST, duplicate
  signer at assemble, OOB signer index, serialise/deserialise
  round-trip, too-short input, bad version byte, and the wire-format
  size formula. _(done; all green)_

---

## Phase N: Polish

- [X] T005 Run `make check`; expect green. _(EXIT=0)_
- [X] T006 The wire-format docs in
  `specs/014-pq-config-chain-redesign/contracts/wire-format.md`
  reference "3294-byte PqSignature wire envelope". The actual size
  is 3310 (per 013's implementation, after FIPS 204 Table 1
  correction). The wire-format contract isn't updated in this PR;
  the source-code comments + `MultiSignedEntry.TupleWireBytes`
  document the correction. A future doc-only PR may update the
  contract text. _(noted in this tasks.md and in
  MultiSignedEntry.scala docstring)_

---

## Notes

- **014 primitive only, not full integration.** The config-chain
  consumer (spec 006) is unimplemented. When 006 lands, it consumes
  this primitive directly — no API changes needed.
- **DST is per-chain.** 014's verify takes the DST as an explicit
  parameter. Spec 006 will own the actual DST string for the live
  config chain (e.g., "siida/config-chain/v1/mainnet"). Spec 015
  uses its own DST ("siida/test/v1/pkg-directory" in tests; spec
  005 will define the production DST).
- **batchVerify driven internally**: `verify` calls
  `PqSignature.batchVerify` to drive the cryptographic check. If
  the batch fails, it falls back to sequential count of valid
  signatures (so the `ThresholdNotMet(count, required)` result has
  an accurate validCount).
- The contract's "3294-byte" mention is a doc bug carried over from
  pre-FIPS-204-confirmation. The actual FIPS 204 ML-DSA-65
  signature size is 3309 bytes. 015's implementation uses the
  corrected size everywhere.
