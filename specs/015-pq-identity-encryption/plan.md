# Implementation Plan: PQ Identity Encryption

**Branch**: `015-pq-identity-encryption` | **Date**: 2026-05-20 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/015-pq-identity-encryption/spec.md`

## Summary

Fourth and final per-primitive PQ migration from the 011 roadmap.
**Protocol-level redesign**, not a primitive swap: Boneh-Franklin
IBE (002) cannot be drop-in-replaced with a PQ scheme because no
production-grade PQ-IBE exists. Replace with a PKG-directory
architecture + `HybridOnion.encrypt` from spec 012.

015's contribution is small: a thin envelope (`IdentityCiphertext`)
that wraps a HybridOnion layer, plus the `Directory` API surface
and a directory-entry verifier that delegates to 014's
`MultiSignedEntry`. The bulk of cryptographic work lives in 012 /
013 / 014.

The privacy threat-model delta — the PKG now sees lookup events —
is the spec's most important commitment. 015 mandates that 005
(PKG) and 007 (SDK) implement anonymous lookup routing via the
mixnet itself.

## Technical Context

**Language/Version**: Scala 3.6.4 / JDK 21 LTS.

**Primary Dependencies**:
- `HybridOnion` from spec 012 (ML-KEM-768 + x25519 hybrid)
- `MultiSignedEntry` from spec 014 (PKG-roster signed directory
  entries)
- `PqSignature` from spec 013 (transitively, via 014)
- No new external dependencies

**Storage**: None at the API surface (directory is opaque; spec
005 owns persistent storage).

**Testing**: munit. Two new files:
- `IdentityEncryptionSuite.scala` — end-to-end encrypt → directory
  lookup → decrypt round-trip; identity-not-found path; tampered-
  directory-entry rejection; HNDL-resistance (transitively via 012)
- `DirectoryVerifierSuite.scala` — `MultiSignedEntry` verification
  paths specific to directory entries

**Target Platform**: Linux/amd64, Linux/arm64, Darwin/arm64.

**Project Type**: Crypto-primitive extension + protocol design.

**Performance Goals**: One encrypt-decrypt round-trip under 100 ms
(SC-006). Dominated by `HybridOnion`'s ML-KEM encap/decap.

**Constraints**:
- API stability per FR-010 once merged
- No new cryptographic dependencies (everything via 012/013/014)
- Directory data structure remains opaque (spec 005 owns the
  concrete implementation)

**Scale/Scope**:
- ~2 new Scala files (api/IdentityEncryption.scala,
  api/Directory.scala — trait + in-memory mock for tests)
- 2 test suites
- 1 KAT JSON file (deferrable per project pattern)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### Principle I — Metadata Privacy is Non-Negotiable (v2.0.0)

**Pass with explicit threat-model amendment.** This spec
documents (in research R2 and `contracts/threat-model.md`) that
the PKG-directory architecture leaks per-query lookups to the
PKG. The mitigation (anonymous routing via the mixnet) is
mandated in FR-007. The constitution-v2.0.0-amended Principle I's
classical-era carve-out covers 002's old Boneh-Franklin IBE
remaining in service until 015 ships; once 015 ships, 002's IBE
moves to deprecated status.

The HNDL-resistance property is inherited from 012's
`HybridOnion`, which already passed its own constitution check.

### Principle II — Spec-Driven, Numbered Feature Workflow

**Pass.** 015 is the fourth and final per-primitive PQ migration
spawned by 011's roadmap, slot reserved.

### Principle III — Licence Integrity

**Pass.** No new dependencies.

### Principle IV — Test-First with Deterministic Rounds

**Pass.** Fixed-seed RNG tests; deterministic outputs.

### Principle V — JVM-Native Mixnet Core

**Pass.** Pure-JVM; everything via existing 012/013/014 surfaces.

### Cross-cutting: Security & Threat Model (v2.0.0)

**Pass with the documented privacy delta** (research R2). The
delta is real — PKG sees lookups that it didn't see with
Boneh-Franklin IBE. Mitigation is anonymous routing, mandatory
in FR-007 for spec 005's implementation. A reviewer should treat
the delta as the load-bearing trade-off of this spec.

### Cross-cutting: Development Workflow & Quality Gates

**Pass.** Standard `make check` covers new files.

### Re-check after Phase 1 design

`contracts/scala-api.md`, `contracts/wire-format.md`, and
`contracts/threat-model.md` are the FR-010 stability surfaces.
No new violations. **PASS.**

## Project Structure

### Documentation (this feature)

```text
specs/015-pq-identity-encryption/
├── plan.md
├── spec.md
├── research.md
├── contracts/
│   ├── scala-api.md       # IdentityEncryption + Directory API
│   ├── wire-format.md     # IdentityCiphertext envelope
│   └── threat-model.md    # PKG-directory privacy trade-off
├── checklists/
│   └── requirements.md
└── tasks.md               # (Phase 2 output)
```

### Source Code (additions only, when implementation lands)

```text
modules/crypto/
├── src/siida/crypto/
│   ├── api/
│   │   ├── IdentityEncryption.scala  # NEW — encrypt/decrypt + IdentityCiphertext
│   │   ├── Directory.scala           # NEW — trait + InMemoryDirectory (tests)
│   │   └── Errors.scala              # EDIT — add IdentityEncError
│   └── internal/
│       └── DirectoryVerifier.scala   # NEW — checks MultiSignedEntry on entries
└── test/src/
    ├── IdentityEncryptionSuite.scala
    └── DirectoryVerifierSuite.scala
```

**Structure Decision**: Standard `api/` + `internal/` split. The
in-memory `Directory` implementation lives under `api/` because
it's a public test/mock fixture; persistent / networked
implementations live in spec 005's source tree.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Item | Note | Why not a violation |
|---|---|---|
| PKG-directory privacy degradation vs original IBE | Real privacy loss | Constitution v2.0.0 explicitly accepts that no production-grade PQ-IBE exists; the migration roadmap (011) committed to this design; mitigation is mandatory in 005 / 007 |

No additional constitutional violations.

## Open coordination items

- **005-pkg-keybootstrap**: implements the persistent directory,
  the lookup-via-mixnet routing, and the onboarding flow that
  populates the directory. This is the load-bearing consumer of
  015.
- **007-client-sdk**: implements the SDK-side caching, anonymous
  query routing, and roster-rotation handling.
- **002-crypto-pairing's IBE**: deprecated when 015 + 005 ship;
  the `siida.crypto.api.IBE` object gets a `@deprecated`
  annotation (same pattern as 013's BLS deprecation).

## What 015 explicitly does NOT decide

- Persistent directory storage format — 005's job
- Anonymous-query routing implementation — 007's job
- PKG roster rotation — 006's job (uses 014's MultiSignedEntry)
- Onboarding flow (how a user gets a `HybridSecretBundle` from the
  PKG initially) — 005's job
- Threshold encryption with multiple PKGs — future spec
- A real PQ-IBE if one becomes standardised — future spec
