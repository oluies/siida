# Implementation Plan: PQ Mixnet Onion Layer (hybrid ML-KEM-768 + x25519)

**Branch**: `012-pq-mixnet-onion-layer` | **Date**: 2026-05-20 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/012-pq-mixnet-onion-layer/spec.md`

## Summary

First per-primitive PQ migration spawned by 011's roadmap. Replaces
the NaCl `box`-based onion-layer encryption with a hybrid handshake:
ML-KEM-768 (BSI TR-02102-1 recommended PQ KEM) + x25519 (classical
ECDH), combined under SHA3-256 with the domain-separation tag
`"siida/hybrid/v1/onion-layer"`. AEAD is ChaCha20-Poly1305.

Library: **Bouncy Castle's PQ provider** — pure-Java, MIT-licensed,
NIST-validated. Avoids the per-arch native-build matrix that 002
introduced for gnark-crypto.

Public API lives at `siida.crypto.api.HybridOnion` and follows the
same FR-010 stability discipline as 002's `IBE` / `BLS` / `BN254`.

Layer composition (three-hop onion construction) is the mixnet
spec's (004) responsibility; 012 ships only the per-layer
primitive plus its KATs.

## Technical Context

**Language/Version**: Scala 3.6.4 (inherited from 001, post-#25
bump), targeting JDK 21 LTS.

**Primary Dependencies**:
- `org.bouncycastle:bcprov-jdk18on:1.78.1` (MIT licence; provides
  ML-KEM-768, x25519, SHA3-256, ChaCha20-Poly1305 in one library)
- All scalac / Pekko / Cats-Effect-3 deps inherited from
  `SiidaModule` (Pekko + CE3 are not used by the crypto module
  per spec 002's FR-012 carve-out, which 012 inherits)

**Storage**: None. Pure computation.

**Testing**: munit + munit-cats-effect (inherited from 001).
Three new test files:
- `MlKem768Suite.scala` — keygen / encap / decap round-trip
  + the committed KAT from `ml_kem_768_kat.json`
- `HybridCombinerSuite.scala` — SHA3-256 combiner KAT
- `HybridOnionSuite.scala` — three-hop onion round-trip, HNDL
  negative test, wire-format roundtrip, alg-ID rejection,
  per-arch determinism

**Target Platform**: Linux/amd64, Linux/arm64, Darwin/arm64 (same
as spec 002). No new arch matrix concerns because Bouncy Castle is
pure-Java.

**Project Type**: Cryptographic primitive library extension to
`modules/crypto/`.

**Performance Goals** (sanity bounds, not tight optimisation):
- Hybrid encap+encrypt one layer in under 50 ms on a typical
  developer laptop
- Hybrid decap+decrypt one layer in under 50 ms
- ML-KEM-768 alone: encap ~1 ms, decap ~1 ms (well under budget)

**Constraints**:
- Cross-architecture determinism for fixed-seed RNG (FR-007)
- Typed-error API: `Either[HybridOnionError, _]` on expected
  failures (FR-005, FR-006); exceptions only on programming bugs
- Deterministic tests; no clock, no network, no flake (Principle IV)
- Wire-format size: ~1137 bytes per layer of envelope overhead;
  documented as a coordination constraint with future spec 004
- All Bouncy Castle dependencies pinned to a specific version
  (FR-011 of spec 001 — no floating ranges)

**Scale/Scope**:
- ~6 new Scala files (api/HybridOnion.scala, api/HybridOnionError
  added to Errors.scala, internal/MlKem.scala, internal/Combiner.scala,
  internal/HybridOnionWire.scala, plus tests)
- ~80 KB BC PQ provider added to runtime classpath
- ~2 KB of new test resources (the two KAT JSON files)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Mapping plan decisions to **constitution v2.0.0** principles.

### Principle I — Metadata Privacy is Non-Negotiable (v2.0.0)

**Pass.** This spec is the first concrete implementation of v2.0.0's
quantum-adversary clause. The hybrid handshake means a quantum-
capable adversary that breaks x25519 retroactively still cannot
decrypt ciphertexts captured today (the ML-KEM share remains
secure). HNDL exposure of the mixnet onion layer is closed by this
spec's implementation, when wired up by spec 004.

Side-channel discipline: the layer code branches only on public
data (algorithm ID, length checks). Decapsulation failures emit
typed errors with NO information about which side (KEM vs ECDH)
failed (uniform error messages per FR-006).

### Principle II — Spec-Driven, Numbered Feature Workflow

**Pass.** Spec lives at `specs/012-pq-mixnet-onion-layer/`. It's
the first of the four PQ migration slots (012-015) reserved by
011's roadmap. The README roadmap row already exists from 011's
merge.

### Principle III — Licence Integrity

**Pass.** New dependency: `org.bouncycastle:bcprov-jdk18on:1.78.1`
— MIT-licensed (their LICENSE.html file). Compatible with AGPL.
No upstream source files are ported into this spec; the BC
provider is used as a binary dependency only. `NOTICE` updated to
credit Bouncy Castle.

ML-KEM-768 reference implementation correctness is BC's
responsibility, validated against NIST CAVP vectors by the BC
project. We rely on BC for the primitive, our code is the
hybrid-handshake glue.

### Principle IV — Test-First with Deterministic Rounds (NON-NEGOTIABLE)

**Pass.** Three test suites, all deterministic (fixed seeds, no
clock, no network). The HNDL-negative test (FR-008) is the
load-bearing per-spec privacy assertion. KATs (FR-009) pin
construction outputs across architectures.

### Principle V — JVM-Native Mixnet Core

**Pass.** Pure-Java Bouncy Castle — no per-arch native binaries
introduced. The JNI complexity (NativeLoader, per-arch matrix CI)
from spec 002's gnark-crypto path does not recur for 012. This is
a positive: the constitution's "smaller dependency surface"
rationale for choosing Mill in V is honoured.

### Cross-cutting: Security & Threat Model (v2.0.0)

**Pass.** This spec is the first concrete migration step per the
roadmap. The hybrid combiner construction is the SHA3-256 hash of
both shared secrets with a domain-separation tag (per 011 R5 and
this spec's R3). No retroactive impact on classical-era specs
(001/002/003) which 011 carved out.

### Cross-cutting: Development Workflow & Quality Gates

**Pass.** Standard `make check` continues to gate every PR. The
parity script is unchanged (no new CI workflows). The
licence-header gate from 001 covers all new files; no upstream
BSD-3-clause headers to preserve (BC is consumed as a binary
dep, not source-included).

### Re-check after Phase 1 design

`data-model.md` is omitted (the wire-format entities live in
`contracts/wire-format.md` which is more explicit about
positional byte layouts). `contracts/scala-api.md` is the FR-010
stability surface. No new violations surface. **PASS.**

## Project Structure

### Documentation (this feature)

```text
specs/012-pq-mixnet-onion-layer/
├── plan.md          # This file
├── spec.md          # Feature specification
├── research.md      # Phase 0: per-decision research (R1–R12)
├── contracts/
│   ├── scala-api.md   # Public HybridOnion API (FR-010 stability gate)
│   └── wire-format.md # Per-layer byte layout, alg-ID space
├── checklists/
│   └── requirements.md
└── tasks.md         # Phase 2 output (/speckit-tasks)
```

### Source Code (additions only)

```text
modules/crypto/
├── src/siida/crypto/
│   ├── api/
│   │   ├── HybridOnion.scala       # Public API (opaque types + object)
│   │   └── Errors.scala            # Extended with HybridOnionError enum
│   └── internal/
│       ├── MlKem.scala             # Bouncy Castle ML-KEM-768 wrapper
│       ├── X25519.scala            # Bouncy Castle x25519 wrapper
│       ├── Combiner.scala          # SHA3-256 hybrid combiner
│       └── HybridOnionWire.scala   # Wire-format serialise/deserialise
└── test/
    ├── src/
    │   ├── MlKem768Suite.scala
    │   ├── HybridCombinerSuite.scala
    │   └── HybridOnionSuite.scala
    └── resources/
        ├── ml_kem_768_kat.json
        └── hybrid_onion_kat.json

build.mill                                # +bcprov-jdk18on dep on modules.crypto
NOTICE                                    # +Bouncy Castle attribution
```

**Structure Decision**: Extension of `modules/crypto/` under
existing `api/` and `internal/` sub-packages. The hybrid is layered
on top of 002's primitives surface (we reuse `Bn254Ops` for nothing
in 012 — ML-KEM is its own world — but the package conventions
match). No new top-level module; the crypto module's
`HybridOnion` is exposed under `siida.crypto.api.HybridOnion`.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Item | Why it's noted | Why it's not a violation |
|---|---|---|
| Bouncy Castle dependency | new runtime dep | Licence-compatible (MIT), pure-Java, NIST-validated; matches Principle V's "pure-JVM where possible" preference |
| Hybrid wire-format overhead (~1137 bytes / layer) | larger than classical | Constitution v2.0.0 Principle I explicitly accepts hybrid-handshake overhead during the PQ migration window; spec 004 will accommodate the cell size |
| Self-referential KATs | external KATs not yet available | Same shape as spec 002's deferral; flagged in research R9 as a follow-up |

No constitutional violations. Items in the table are
project-level notes for the audit trail.

## Open coordination items for future specs

- **004-mixnet-server**: cell size must accommodate ~3.4 KB
  three-hop overhead. Recommendation in research R7 is ~4 KB
  cells; 004 makes the final call.
- **005-pkg-keybootstrap**: must distribute hybrid public bundles
  rather than just x25519 public keys.
- **007-client-sdk**: clients consume `HybridOnion.encrypt` to
  build outgoing onions; the multi-hop composition pattern is
  the SDK's concern.
- **016-observability**: per-operation timing metrics (NEVER
  per-recipient timing) for hybrid encap/decap should land when
  the observability spec opens.

## What this spec does NOT decide

- The exact multi-hop onion composition pattern (that's 004 / 007).
- The eventual PQ-only cutover schedule.
- Whether to bump the classical half to Curve448 — separate spec.
- The hybrid public bundle's distribution mechanism (PKG side).
