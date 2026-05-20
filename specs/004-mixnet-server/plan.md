# Implementation Plan: Mixnet Server

**Branch**: `004-mixnet-server` | **Date**: 2026-05-20 | **Spec**: [spec.md](./spec.md)

## Summary

Wire `HybridOnion` (012) into Vuvuzela's round-based mix chain.
MVP scope: single-JVM, in-memory, synchronous round execution
through a 3-mixer fixture. Pekko Streams provides the
mixer-to-mixer pipeline within one process. Distributed
deployment, persistent state, crash recovery, and live roster
rotation are deferred to follow-up specs.

The core algorithm: each client builds an N-layer
`HybridOnion`-stack (one layer per mixer) plus an inner
`(mailbox_id, payload)` envelope. The coordinator runs the batch
through the chain: each mixer peels its layer, shuffles the batch
deterministically given a per-round seed, forwards. The last
mixer emits the inner envelopes; recipients claim from their
mailbox.

## Technical Context

**Language/Version**: Scala 3.6.4 / JDK 21 LTS (inherited).

**Primary Dependencies**:
- `modules.crypto` (HybridOnion API, PqSignature, IdentityEncryption — all on main)
- `org.apache.pekko::pekko-stream:1.1.5` (already in default SiidaModule deps)
- `org.typelevel::cats-effect:3.5.7` (inherited; used minimally for IO wrapping if needed)

**Storage**: None in MVP. All round state is in-memory and
ephemeral.

**Testing**: munit (inherited). Four suites planned:
- `MixChainSuite` — client-side layered-encrypt + decode
- `MixerSuite` — single-mixer peel + shuffle, plus the integrity
  property test from US2
- `RoundSuite` — coordinator end-to-end round
- `CoverTrafficSuite` — US3 indistinguishability

**Target Platform**: Linux/amd64, Linux/arm64, Darwin/arm64.
Pure-Java (Pekko is Scala/JVM); no native code.

**Project Type**: Mixnet runtime module — first production-grade
non-crypto module. Establishes the pattern for 005/006/007.

**Performance Goals** (sanity bounds, MVP):
- 3-mixer / 8-client / 256-byte-payload round under 500 ms
- Per-mixer peel under 50 ms (dominated by HybridOnion.decrypt)

**Constraints**:
- Coordinator.runRound must be a pure deterministic function
  (FR-003)
- No global mutable state in mixers
- Wire format between mixers = HybridOnion.OnionLayer bytes only
  (FR-006) — no per-mixer framing

**Scale/Scope**:
- 5-6 new Scala files under `modules/mixnet/src/`
- 4 new test files under `modules/mixnet/test/src/`
- 1 new ivyDeps line for `modules.mixnet` to depend on
  `modules.crypto`

## Constitution Check

### Principle I — Metadata Privacy is Non-Negotiable (v2.0.0)

**Pass.** The mixnet IS the metadata-privacy mechanism. Crypto
layer (012) is HNDL-resistant; the shuffle composes that into
sender-recipient unlinkability over a single round.

### Principle II — Spec-Driven, Numbered Feature Workflow

**Pass.** 004's slot was reserved in 001's roadmap; the spec lands
now per the user's pickup order. No skips.

### Principle III — Licence Integrity

**Pass.** No new dependencies. Pekko (Apache 2.0) already in
service.

### Principle IV — Test-First with Deterministic Rounds

**Pass.** This is exactly the spec that establishes the
deterministic-round discipline as a tested property (FR-003).

### Principle V — JVM-Native Mixnet Core

**Pass.** Pekko Streams is JVM-native; no JNI, no per-arch matrix.

### Cross-cutting: Security & Threat Model (v2.0.0)

**Pass.** The mixer-integrity test (US2) demonstrates that a
single mixer can't learn cross-layer information. HNDL-resistance
is inherited from 012's HybridOnion.

### Cross-cutting: Development Workflow & Quality Gates

**Pass.** `make check` covers the new suites; no CI workflow
changes.

## Project Structure

### Documentation (this feature)

```text
specs/004-mixnet-server/
├── plan.md
├── spec.md
├── research.md
├── contracts/
│   ├── scala-api.md
│   └── wire-format.md
├── checklists/
│   └── requirements.md
└── tasks.md            # generated late
```

### Source Code (new module surface)

```text
modules/mixnet/
├── src/
│   ├── siida/mixnet/api/
│   │   ├── MixChain.scala        # client-side layered encryption
│   │   ├── Mixer.scala           # peel-and-shuffle one layer
│   │   ├── Coordinator.scala     # orchestrate a round
│   │   ├── RoundConfig.scala     # roster + per-round seeds
│   │   └── Errors.scala          # MixerError, CoordinatorError
│   └── siida/mixnet/internal/
│       └── Shuffle.scala         # deterministic shuffle helper
└── test/
    └── src/
        ├── MixChainSuite.scala
        ├── MixerSuite.scala
        ├── RoundSuite.scala
        └── CoverTrafficSuite.scala
```

`build.mill` updated: `modules.mixnet.moduleDeps += modules.crypto`.

**Structure Decision**: keep all mixnet code under
`modules/mixnet/` with the public API at `siida.mixnet.api.*`
matching the project-wide convention. Internal shuffle helper is
under `siida.mixnet.internal.*` (same convention as 012's
`siida.crypto.internal.*`).

## Complexity Tracking

| Item | Note | Why not a violation |
|---|---|---|
| Skipping Pekko Actors for the coordinator | Plan + spec text mention Pekko Streams; coordinator is implemented as a pure function for the MVP | Pekko Streams is used for the mixer-to-mixer pipeline. Coordinator as a pure function is the right shape for FR-003 (deterministic round); actor-based coordination is a network-protocol concern (deferred spec) |
| Single-JVM only | The spec text emphasises "deferred" | Distributed deployment is explicitly out-of-scope per spec's "out-of-scope" subsection |
| No persistent state | Same | Same — MVP correctness first; persistence is operational concern |
| Deterministic shuffle from fixed seed | Could be perceived as weakening security | Seed unpredictability is the security property; determinism-given-seed is the testability property. Production seeds are CSPRNG-drawn per round per mixer. |

## Open coordination items

- **Spec 005 (PKG)** will provide the actual mixer roster and
  mailbox-id space. 004 takes these as static configuration.
- **Spec 006 (config-chain)** rotates the roster. 004 has no
  rotation logic — that's a follow-up integration spec.
- **Spec 007 (SDK)** is the client side: cover-traffic timing,
  retry, config-chain verification. 004 provides the underlying
  `MixChain.layeredSubmission` and `MixChain.coverSubmission`
  helpers for the SDK to call.
- **Spec 018 (observability)** instruments 004's runtime with
  OTEL. Stub `Coordinator.RoundMetrics` returned by `runRound`
  in the MVP — counts (submissions in, submissions out, drops,
  per-mixer timings) but no telemetry export.

## What 004 explicitly does NOT do

- Does NOT define a network transport
- Does NOT persist round state to disk
- Does NOT implement crash recovery
- Does NOT support live mixer-key rotation
- Does NOT support cross-round batching
- Does NOT do verifiable shuffles (security model doesn't require it)
