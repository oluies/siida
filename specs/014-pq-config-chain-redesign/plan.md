# Implementation Plan: PQ Config-Chain Redesign

**Branch**: `014-pq-config-chain-redesign` | **Date**: 2026-05-20 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/014-pq-config-chain-redesign/spec.md`

## Summary

Third per-primitive PQ migration from the 011 roadmap. **Pure design
spec** — the deliverable is the `MultiSignedEntry` primitive (verifier
+ wire format) that spec 006-config-chain-governance will consume
when it's authored. 014 implements only the per-entry cryptographic
piece, not the full chain (consensus, replay protection, network
distribution, etc. — all 006's job).

No new dependency. The cryptographic surface is entirely
`PqSignature.batchVerify` from 013 + SHA3-256 (JDK built-in).

## Technical Context

**Language/Version**: Scala 3.6.4 / JDK 21 LTS.

**Primary Dependencies**:
- `PqSignature` from spec 013 (provides ML-DSA-65 sign / verify /
  batchVerify)
- JDK 21 `MessageDigest.getInstance("SHA3-256")`
- No new external dependencies

**Storage**: None.

**Testing**: munit. Two new files:
- `MultiSignedEntrySuite.scala` — verifier-predicate tests covering
  US1 acceptance scenarios 1-4, threshold variations, duplicate
  signer, invalid index, hash mismatch, empty list
- `MultiSignedEntryWireSuite.scala` — wire-format round-trip,
  version-tag rejection, signer-list ordering tolerance

**Target Platform**: Linux/amd64, Linux/arm64, Darwin/arm64.

**Project Type**: Crypto-primitive extension.

**Performance Goals**: 8-signer 3-of-8 verify under 100 ms (SC-001).
Limited by `PqSignature.batchVerify(8)` cost.

**Constraints**:
- Wire format pinned in `contracts/wire-format.md`
- Verifier predicate tolerant of signer-list reordering
- Verifier intolerant of duplicate signer_index

**Scale/Scope**:
- ~2 new Scala files (api/MultiSignedEntry.scala, internal/MultiSignedEntryCodec.scala)
- 2 test suites
- 1 KAT JSON file (deferrable per the 002/012/013 pattern)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### Principle I — Metadata Privacy is Non-Negotiable (v2.0.0)

**Pass.** Config-chain entries are public by design (everyone needs
to verify them). Quantum-adversary scope satisfied by the ML-DSA-65
delegation through 013. No side channels — `ThresholdNotMet` carries
only count info, not signer identity (research R6).

### Principle II — Spec-Driven, Numbered Feature Workflow

**Pass.** 014 is the third per-primitive PQ migration in the 011
roadmap, slot reserved.

### Principle III — Licence Integrity

**Pass.** No new dependencies.

### Principle IV — Test-First with Deterministic Rounds

**Pass.** All tests use fixed-seed RNG. Verifier predicate has
deterministic semantics — no clock, no network, no flake.

### Principle V — JVM-Native Mixnet Core

**Pass.** Pure-JVM; the only crypto is via 013's `PqSignature`.

### Cross-cutting: Security & Threat Model (v2.0.0)

**Pass.** Per-chain domain-separation tag prevents cross-chain
signature replay. SHA3-256 hash binding prevents payload tampering
after signing. Per-signer indices prevent duplicate-signer attacks.

### Cross-cutting: Development Workflow & Quality Gates

**Pass.** Standard `make check`; licence-header gate covers new
files.

### Re-check after Phase 1 design

`data-model.md` not needed (the wire-format doc serves the same
purpose at a more concrete level). `contracts/scala-api.md` plus
`contracts/wire-format.md` are the FR-010 stability surface.
**PASS.**

## Project Structure

### Documentation (this feature)

```text
specs/014-pq-config-chain-redesign/
├── plan.md
├── spec.md
├── research.md
├── contracts/
│   ├── scala-api.md       # MultiSignedEntry verify API
│   └── wire-format.md     # Byte layout of an entry
├── checklists/
│   └── requirements.md
└── tasks.md               # (Phase 2 output)
```

### Source Code (additions only, when implementation lands)

```text
modules/crypto/
├── src/siida/crypto/
│   ├── api/
│   │   ├── MultiSignedEntry.scala  # NEW — opaque type + verify
│   │   └── Errors.scala            # EDIT — add MultiSignedEntryError
│   └── internal/
│       └── MultiSignedEntryCodec.scala # NEW — wire-format pack/unpack
└── test/src/
    ├── MultiSignedEntrySuite.scala     # NEW
    └── MultiSignedEntryWireSuite.scala # NEW
```

**Structure Decision**: Same `api/` + `internal/` pattern as 012
and 013.

## Complexity Tracking

No constitutional violations. The "lose aggregation" cost is
inherited from 013 and explicitly documented as a project-level
project decision rather than a per-spec violation.

## Coordination with future specs

- **006-config-chain-governance**: when authored, MUST consume
  `MultiSignedEntry` for per-entry cryptography. 006 picks the
  payload encoding, threshold M, roster epoch transitions,
  consensus, and replay protection.
- **005-pkg-keybootstrap**: signs roster epoch transitions and
  PKG master-key publications via `MultiSignedEntry`.
- **016-observability** (sketched): metrics on
  `ThresholdNotMet(validCount, required)` give operators visibility
  into how close governance is to losing quorum.

## What 014 explicitly does NOT decide

- The payload encoding for config entries (CBOR vs protobuf vs
  custom) — that's 006.
- The genesis-entry bootstrap procedure — 006.
- The threshold M for any specific chain instance — 006.
- The replay-protection scheme (sequence numbers, hash-chaining
  of entries) — 006.
- Network distribution and consensus — 006.
