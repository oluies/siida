# Implementation Plan: Crypto Pairing (BN254 + IBE + BLS)

**Branch**: `002-crypto-pairing` | **Date**: 2026-05-17 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/002-crypto-pairing/spec.md`

## Summary

Port the Vuvuzela `crypto/ibe` (Boneh-Franklin IBE) and `crypto/bls`
(BLS signatures with aggregation and proofs-of-possession) packages
onto a BN254 pairing primitive that runs on the JVM. Resolves the
spec-deferred FR-009 decision: **gnark-crypto reached over a thin JNI
shim with pre-built per-architecture native binaries**, with a small
JNA layer in Scala and ported BSD-3-clause source kept under the
existing licence-header allowlist mechanism. The chosen path satisfies
the cross-architecture-determinism, licence-integrity, and
audit-surface constraints from the constitution; the rejected
alternatives (pure-Scala BN254 from scratch; existing pure-Java BN254
libs; Herumi mcl; subprocess to gnark-crypto) are recorded in
`research.md` R1.

Public Scala API surface is locked in `contracts/scala-api.md`
(FR-010); the C ABI exposed by the native shim is locked in
`contracts/native-abi.md`; crypto-module-specific threat-model
commitments live in `contracts/threat-model.md`.

## Technical Context

**Language/Version**: Scala 3.6.x (inherited from 001), targeting
JDK 21 LTS. The native shim is C (compiled by cgo from gnark-crypto
Go sources); Go is only needed by the GitHub Actions matrix that
regenerates per-arch binaries, NOT by developer machines.

**Primary Dependencies**:
- `net.java.dev.jna:jna:5.14.0` (FFI; Apache-2.0 chosen from JNA's
  Apache-2.0 / LGPL-2.1 dual licence)
- All scalac/Pekko/Cats-Effect-3 dependencies inherited from
  `SiidaModule` (Pekko + CE3 are present but unused by the crypto
  module per FR-012)

**Storage**: None. The crypto module is pure computation.

**Testing**: munit + munit-cats-effect3 (inherited from 001) for
test runner. Known-answer test vectors live under
`modules/crypto/test/resources/` as committed JSON files; sources
recorded in `research.md` R8. No use of CE3's `IO` in the test bodies
(the crypto API is synchronous by design).

**Target Platform**: JVM 21 LTS on Linux/amd64, Linux/arm64,
Darwin/amd64, Darwin/arm64. Native shim binaries shipped pre-built
for all four; per `research.md` R4 the GitHub Actions matrix
regenerates them on demand.

**Project Type**: Cryptographic-primitives library module. Pure-
computation API consumed by downstream modules (`pkg`,
`configchain`, `sdk`, `agent`).

**Performance Goals** (from `spec.md` SC-004; deliberately loose
sanity bounds):
- BN254 pairing < 50ms on a typical developer laptop
- IBE encrypt < 100ms
- BLS sign < 50ms
- JNA call overhead is single-digit microseconds; not a budget
  concern at this scale

**Constraints**:
- Cross-architecture determinism: serialised outputs MUST be
  byte-identical on Linux/amd64 vs macOS/arm64 (FR-004, SC-002)
- Typed-error API: no exceptions for expected failure modes
  (FR-005); exceptions only for programming bugs and resource
  failures (native lib failed to load)
- Deterministic tests: fixed-seed RNG, no clock, no network
  (FR-006, Constitution Principle IV)
- Licence integrity: ported files keep BSD-3-clause via the
  existing `build/licence-headers/ported.json` allowlist (FR-008,
  Constitution Principle III)
- The crypto module MUST NOT introduce telemetry or persistent
  state (FR-012, Constitution Principle I)
- Public Scala API frozen after 002 merges; downstream changes are
  spec-level events (FR-010)

**Scale/Scope**:
- ~12 native C functions (see `contracts/native-abi.md`)
- ~30 public Scala symbols across `IBE`, `BLS`, `BN254` (see
  `contracts/scala-api.md`)
- Native binary size: ~3 MB per arch (gnark-crypto BN254 subset)
- Test-vector resources: ~50 KB JSON

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Mapping plan decisions to constitution v1.0.0 principles.

### Principle I — Metadata Privacy is Non-Negotiable

**Pass.** The crypto module introduces no traffic-carrying code, no
logging, no telemetry, and no persistent state (FR-012). Every
operation is pure-computation through the FFI. The native shim does
not log either. The IBE `identityTag` field on ciphertexts is a
*public* 16-byte hint that exists for cheap wrong-key rejection; it
is not derived from any secret. Re-check post-Phase-1: still pass —
`data-model.md` confirms no entity carries logging or persistence
state.

### Principle II — Spec-Driven, Numbered Feature Workflow

**Pass.** 002 lives under `specs/002-crypto-pairing/` with `spec.md`,
`plan.md`, `research.md`, `quickstart.md`, `data-model.md`,
`contracts/{scala-api.md, native-abi.md, threat-model.md}`, and a
spec-quality checklist. The roadmap order (002 before 003-008) is
preserved.

### Principle III — Licence Integrity (AGPL-3.0-or-later Compatible Only)

**Pass.** New dependencies in 002:
- `net.java.dev.jna:jna:5.14.0` — Apache-2.0 (chosen from JNA's
  dual licence) ✓
- `consensys/gnark-crypto` (used inside the native shim) — Apache-2.0 ✓
- Native binaries are produced from Apache-2.0 source via Go's
  cgo + `c-shared` build mode; the resulting `.so` / `.dylib`
  files carry no additional licence and are distributed as part of
  the AGPL-3.0-or-later Siida release.

Ported source files from `github.com/vuvuzela/crypto` (BSD-3-clause)
retain their headers and are listed in `build/licence-headers/ported.json`
so the licence-header gate from 001 FR-010 treats them correctly.
The `NOTICE` file is amended to credit `consensys/gnark-crypto`
(the constitution's `R7` and `NOTICE` both anticipate this).

### Principle IV — Test-First with Deterministic Rounds (NON-NEGOTIABLE)

**Pass.** Test vectors from external sources (`research.md` R8) are
written and committed BEFORE the implementing code is written;
contributors verifying the IBE / BLS / BN254 paths will fail-then-pass
each suite. There are no rounds in 002 (rounds are 004 territory),
but the cross-architecture-determinism requirement (FR-004, SC-002)
is the moral equivalent: a single committed byte-output is the
oracle, fixed-seed RNG eliminates non-determinism, and the test
harness diffs serialised actual against expected.

### Principle V — JVM-Native Mixnet Core (Scala 3 + Pekko + Cats Effect 3)

**Pass with explicit acknowledgement of the JNI path.** The
constitution's Principle V text says:
> Native code reached over JNI (e.g., gnark-crypto) MUST ship
> pre-built binaries or build hermetically for every supported
> architecture; otherwise a pure-Scala fallback MUST exist.

We ship pre-built binaries for four architectures (`research.md`
R4). The crypto module's Scala code stays inside the Pekko /
CE3 / Mill ecosystem (though it imports neither Pekko nor CE3 in
practice — FR-012). The build (Mill 0.12) and bootstrap (`./mill`,
`make`) are unchanged from 001.

A pure-Scala fallback is NOT provided in 002; the constitution
permits this when pre-built binaries cover every supported
architecture. If a fifth architecture is added that we cannot
pre-build for, the spec must amend to either add it to the matrix
job or introduce a fallback path. This is recorded as a future
amendment trigger.

### Cross-cutting: Security & Threat Model

**Pass.** Constant-time guarantees and known non-goals are
documented in `contracts/threat-model.md` (per-operation table).
The Scala layer branches only on public data; secret-touching
arithmetic is pushed into gnark-crypto's constant-time
implementations.

### Cross-cutting: Development Workflow & Quality Gates

**Pass.** `make headers` continues to gate every PR (the ported-file
allowlist mechanism is unchanged from 001). `make ci-parity` continues
to pass (the new native-build matrix workflow is *separate* from the
existing `.github/workflows/ci.yml` and `.forgejo/workflows/ci.yml`,
which it does not modify). Dual CI continues to validate every PR
(GitHub Actions canonical, Forgejo Actions mirror); the native
binary regeneration job runs only on the GitHub side because
Forgejo's runners differ per-arch.

### Re-check after Phase 1 design

`data-model.md` and `contracts/` introduce no surprises; no
violations surface. The choice to ship native binaries in the JAR
(via `resources/`) is a Mill conventions move, not a principle
violation. **PASS.**

## Project Structure

### Documentation (this feature)

```text
specs/002-crypto-pairing/
├── plan.md              # This file
├── spec.md              # Feature specification
├── research.md          # Phase 0: implementation-strategy decision (R1-R12)
├── data-model.md        # Phase 1: entities + validation
├── quickstart.md        # Phase 1: contributor entry point
├── contracts/
│   ├── scala-api.md     # Public Scala API (FR-010 stability gate)
│   ├── native-abi.md    # C ABI exposed by the native shim
│   └── threat-model.md  # Crypto-module-specific threat model
├── checklists/
│   └── requirements.md  # Spec quality checklist
└── tasks.md             # Phase 2 output (created by /speckit-tasks)
```

### Source Code (repository root, additions only)

```text
modules/crypto/
├── README.md                              # updated: name 002 spec slot specifically
├── src/
│   └── siida/crypto/
│       ├── api/
│       │   ├── IBE.scala                  # opaque types + IBE object (contracts/scala-api.md)
│       │   ├── BLS.scala                  # opaque types + BLS object
│       │   ├── BN254.scala                # lower-level primitives (US3)
│       │   ├── Errors.scala               # IBEError, BLSError, BN254Error enums
│       │   └── package.scala              # public re-exports
│       └── internal/
│           ├── NativeLoader.scala         # JVM-startup loader; arch detection
│           ├── Native.scala               # JNA interface (mirrors contracts/native-abi.md)
│           ├── BytesOps.scala             # fixed-size byte buffer helpers
│           ├── HashToCurve.scala          # DST construction; calls into Native
│           ├── Kdf.scala                  # HKDF-SHA-256 with domain-separated tags
│           └── ported/
│               └── (BSD-3-clause files copied from vuvuzela/crypto if any survive porting)
├── test/
│   ├── src/
│   │   ├── BN254VectorsSuite.scala        # KAT for BN254 primitives
│   │   ├── HashToCurveSuite.scala         # KAT for SSWU
│   │   ├── IBESuite.scala                 # round-trip + wrong-identity + KAT
│   │   ├── BLSSuite.scala                 # sign/verify/aggregate/PoP + KAT
│   │   └── DeterminismSuite.scala         # cross-arch byte-for-byte oracle checks
│   └── resources/
│       ├── bn254_vectors.json             # gnark-crypto sourced; commit hash in header
│       ├── sswu_vectors.json              # IETF draft sourced
│       ├── bls_vectors.json               # gnark-crypto sourced
│       └── ibe_vectors.json               # generated via fixed-seed reference; documented
└── native/
    ├── README.md                          # how to rebuild; arch matrix
    ├── shim.c                             # the C ABI implementation (~200 lines)
    ├── go.mod                             # gnark-crypto pin
    ├── go.sum                             # checked in
    ├── main.go                            # tiny cgo `c-shared` wrapper exporting shim symbols
    ├── build.sh                           # one-shot per-arch build invoked by CI matrix
    ├── linux-amd64/libsiida_bn254.so
    ├── linux-arm64/libsiida_bn254.so
    ├── darwin-amd64/libsiida_bn254.dylib
    └── darwin-arm64/libsiida_bn254.dylib

build/licence-headers/ported.json          # updated: add any ported BSD-3-clause source paths

NOTICE                                     # amended: credit consensys/gnark-crypto

.github/workflows/native-build.yml         # NEW: workflow_dispatch + on-shim-change matrix build,
                                           # opens a PR with regenerated binaries

build.mill                                 # updated: add JNA dep to crypto module + resources override
```

**Structure Decision**: Single-module addition to the existing 001
layout. The crypto module's three-way split (`api/`, `internal/`,
`internal/ported/`) makes licence provenance unambiguous file-by-file
and gives `make headers` a clean target. The `native/` directory
co-located with the Scala sources keeps the Go + C build artefacts
discoverable; the per-arch binary subdirectories let JNA load by
`os.name + os.arch` without scanning. The native-build CI workflow
lives next to the existing CI workflows but is *not* in the
parity-checked path — it's a separate concern from the per-PR build
gate.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|--------------------------------------|
| Introducing a per-arch native binary distribution | Pure-Scala BN254 would require a multi-month from-scratch crypto implementation effort that is not Siida's privacy-relevant differentiator | Pure-Scala BN254: implementation + audit risk dominate; Apache Milagro / web3j: insufficient BN254 maturity (research R1) |
| Adding a Go-based build pipeline (CI-only) | Required to produce `libsiida_bn254` per-arch from the chosen gnark-crypto upstream | Bundling third-party pre-builts: provenance uncertain; subprocess-to-gnark binary: per-call latency unacceptable |
| JNA as a new runtime dep | Cheapest stable JVM FFI option that works on the constitution-pinned JDK 21 | Panama FFM: incubator status in JDK 21, requires `--enable-preview`; raw JNI: verbose, no functional advantage |

Strictly speaking these are not constitutional violations — Principle
V explicitly accommodates JNI with pre-built binaries — but they are
the new project-level complexity 002 introduces, so they belong in
this table for the audit trail. Downstream specs (003-008) inherit
this complexity without re-litigating it.
