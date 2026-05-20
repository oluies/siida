# Implementation Plan: PQ BLS Replacement (ML-DSA-65)

**Branch**: `013-pq-bls-replacement` | **Date**: 2026-05-20 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/013-pq-bls-replacement/spec.md`

## Summary

Second per-primitive PQ migration from the 011 roadmap. Adds
`siida.crypto.api.PqSignature` over ML-DSA-65 (FIPS 204) via the
Bouncy Castle PQ provider already in `modules.crypto`. No new
dependency; no JNI. The existing classical `BLS` API gets a
`@deprecated` annotation but stays compilable so 002's BLSSuite
continues to pass.

The aggregation property of BLS is **lost by design** — no PQ
aggregate signature scheme is production-grade. Spec 014
config-chain-redesign handles the downstream consequence.

## Technical Context

**Language/Version**: Scala 3.6.4 / JDK 21 LTS (inherited).

**Primary Dependencies**:
- `org.bouncycastle:bcprov-jdk18on:1.78.1` (already in
  `modules.crypto` from spec 012; provides ML-DSA via the
  `pqc.crypto.crystals.dilithium` package — BC kept the legacy
  Dilithium name; algorithm is FIPS 204 ML-DSA-65)

**Storage**: None. Pure-computation primitive.

**Testing**: munit (inherited). Two new files:
- `PqSignatureSuite.scala` — sign/verify round-trip, forgery
  negative tests, serialise/deserialise, batchVerify
- `MlDsa65Suite.scala` — direct BC wrapper tests (sizes,
  keygen/sign/verify round-trip, determinism)

**Target Platform**: Linux/amd64, Linux/arm64, Darwin/arm64. No
new JNI surface.

**Project Type**: Crypto-primitive extension (same shape as 012).

**Performance Goals** (sanity bounds):
- ML-DSA-65 sign: < 50 ms on a typical laptop
- ML-DSA-65 verify: < 50 ms
- `batchVerify(8)`: ≥ 1.5× faster than 8 sequential `verify` calls

**Constraints**:
- Cross-arch determinism with fixed-seed RNG
- API stability per FR-010 once merged
- BLS over BN254 stays compilable (deprecation only)

**Scale/Scope**:
- ~3 new Scala files (api/PqSignature.scala, internal/MlDsa.scala,
  internal/MlDsaBatchVerify.scala) + 2 test suites
- 1 new KAT JSON file (deferrable per the 002/012 pattern)
- 1 deprecation annotation on `BLS` object

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### Principle I — Metadata Privacy is Non-Negotiable (v2.0.0)

**Pass.** Signatures are public; metadata privacy is unaffected by
013's design. Quantum-adversary scope (v2.0.0) is satisfied by
the choice of ML-DSA-65. No telemetry / no logging additions.

### Principle II — Spec-Driven, Numbered Feature Workflow

**Pass.** 013 is the second per-primitive PQ migration in the 011
roadmap, with its slot reserved by 011 / README.

### Principle III — Licence Integrity

**Pass.** No new dependencies; Bouncy Castle (MIT) already in
service from 012.

### Principle IV — Test-First with Deterministic Rounds

**Pass.** All tests use fixed-seed SHA1PRNG; no clock, no network.
`batchVerify` correctness covered by both positive (8 valid) and
negative (one tampered) tests. The forgery-resistance assertions
are the load-bearing security property.

### Principle V — JVM-Native Mixnet Core

**Pass.** Pure-Java; no new JNI surface.

### Cross-cutting: Security & Threat Model (v2.0.0)

**Pass.** Forward-secrecy concern (HNDL) does not apply to
signatures; the relevant threat is forgery once Shor exists. The
v2.0.0 amendment's classical-era carve-out covers existing BLS
usage in 002.

### Cross-cutting: Development Workflow & Quality Gates

**Pass.** No CI workflow changes. `make check` covers new files.
Licence-header gate applies to all new sources.

### Re-check after Phase 1 design

`data-model.md` not needed (signature scheme has no real entity
diagram). `contracts/scala-api.md` is the FR-010 stability surface.
No new violations. **PASS.**

## Project Structure

### Documentation (this feature)

```text
specs/013-pq-bls-replacement/
├── plan.md
├── spec.md
├── research.md
├── contracts/
│   └── scala-api.md          # PqSignature public API
├── checklists/
│   └── requirements.md
└── tasks.md                  # (Phase 2 output)
```

### Source Code (additions only)

```text
modules/crypto/
├── src/siida/crypto/
│   ├── api/
│   │   ├── PqSignature.scala     # NEW — opaque types + sign/verify/batchVerify
│   │   ├── BLS.scala             # EDIT — add @deprecated annotation
│   │   └── Errors.scala          # EDIT — add PqSignatureError enum
│   └── internal/
│       ├── MlDsa.scala           # NEW — BC ML-DSA-65 keygen/sign/verify
│       └── MlDsaBatchVerify.scala # NEW — Scala-layer batched verify (~0.6n cost)
└── test/src/
    ├── PqSignatureSuite.scala    # NEW
    └── MlDsa65Suite.scala        # NEW
```

**Structure Decision**: Same shape as 012. The `internal/` wrappers
isolate BC API surface; the `api/` object is the FR-010 stability
gate.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Item | Note | Why not a violation |
|---|---|---|
| Scala-layer batched ML-DSA verify | New non-trivial code | BC doesn't provide a native batch API yet; standard randomised-coefficient construction (R3); migrates to BC native when it lands |
| @deprecated on BLS | Backward-compat shim | Constitution v2.0.0's classical-era carve-out explicitly retains BLS until per-feature migration |

No constitutional violations. Items are project-level notes.

## Open coordination items

- **006-config-chain-governance**: the canonical BLS-aggregate
  consumer. 014 redesigns the chain around per-signer ML-DSA +
  batchVerify; 006 will adopt that shape directly.
- **004-mixnet-server**: mixer attestations will switch from BLS
  to `PqSignature` when 004 ships.
- **008-agent-messaging**: future agent identity proofs use
  `PqSignature` from day one (no BLS-over-BN254 to migrate from).
