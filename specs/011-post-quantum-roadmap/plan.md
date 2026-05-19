# Implementation Plan: Post-Quantum Roadmap

**Branch**: `011-post-quantum-roadmap` | **Date**: 2026-05-19 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/011-post-quantum-roadmap/spec.md`

## Summary

Roadmap spec, not a code-shipping feature. The concrete deliverables
are (1) a constitution amendment adding quantum adversaries to the
threat model, (2) the per-primitive replacement table in
[research.md](./research.md), (3) four reserved spec slots
(012–015) for per-primitive PQ migrations, and (4) a corresponding
README roadmap update.

European certification anchoring (preference: BSI TR-02102-1, then
ANSSI, then ENISA; tracked Swedish research provenance where it
breaks ties).

## Technical Context

**Language/Version**: N/A — this spec ships markdown.

**Primary Dependencies**: None (no code).

**Storage**: N/A.

**Testing**: N/A. The spec's success criteria (SC-001 through
SC-006) are review-time checks against the documents, not automated
tests.

**Target Platform**: N/A.

**Project Type**: Roadmap / governance feature.

**Performance Goals**: A reviewer can answer "what's the PQ
replacement for primitive X?" in under 60 seconds (SC-002). The
research table is structured to make that lookup direct.

**Constraints**:
- Constitution Principle II: this lives in `specs/011-post-quantum-roadmap/`.
- Constitution Principle III: PQ scheme choices MUST be
  licence-compatible (almost all NIST-finalist implementations are
  Apache-2.0 or BSD).
- Constitution Principle V: pure-JVM-where-possible; if a PQ
  primitive requires JNI to a C implementation, the same pre-built
  per-arch-binary discipline from spec 002 applies.

**Scale/Scope**: 3 documents (spec, plan, research); 1 README
edit; 0 code changes; 1 sketched constitution amendment.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### Principle I — Metadata Privacy is Non-Negotiable

**Pass with proposed amendment.** The spec itself documents that the
*current* Principle I is silent on quantum adversaries; the roadmap's
core deliverable is to amend it. No code introduced in 011 weakens
the current privacy posture.

### Principle II — Spec-Driven, Numbered Feature Workflow

**Pass.** Lives in `specs/011-post-quantum-roadmap/`; reserves four
forward slots (012–015) for the per-primitive migration specs it
spawns. Bumps the sketched `011-observability` slot to `016` in the
README roadmap.

### Principle III — Licence Integrity

**Pass (forward-looking).** This spec ships no code so introduces
no dependencies. The per-primitive specs will each have to declare
their PQ library choice and pass III at that point. Notes in
research.md flag that Bouncy Castle's PQ implementations are MIT-
licensed, ML-KEM reference implementations are Apache-2.0; both
compatible.

### Principle IV — Test-First with Deterministic Rounds

**Pass (N/A for roadmap).** Hybrid handshake combiner correctness
is testable when the first per-primitive spec lands (012).

### Principle V — JVM-Native Mixnet Core

**Pass (forward-looking).** Per-primitive specs may use JNI for PQ
libs (BoringSSL, liboqs, libcrux) or stay pure-JVM via Bouncy
Castle's PQ providers. Decision is per-spec, same as spec 002's
gnark-crypto choice.

### Cross-cutting: Security & Threat Model

**The spec's own subject.** Pass with explicit amendment proposed.

### Cross-cutting: Development Workflow & Quality Gates

**Pass.** Standard `make check` continues to pass (no code change).
Per-PR CI parity script unchanged.

### Re-check after Phase 1 design

No `data-model.md` or `contracts/` are required — roadmap specs
have neither domain entities nor an API surface. **PASS.**

## Project Structure

### Documentation (this feature)

```text
specs/011-post-quantum-roadmap/
├── plan.md       # This file
├── spec.md       # The roadmap proposition
└── research.md   # Per-primitive replacement table + European cert + Swedish provenance
```

`tasks.md` is intentionally omitted: the "tasks" of this roadmap
are themselves entire numbered specs (012, 013, 014, 015) plus the
constitution amendment, none of which decompose into the granular
per-implementation tasks the tasks-template expects.

### Source Code (repository root)

```text
README.md                                # roadmap table: insert 011, 012, 013, 014, 015; bump observability to 016
.specify/memory/constitution.md          # SEPARATE follow-up: constitution amendment via /speckit-constitution
```

**Structure Decision**: Roadmap-only. No code lands in 011. The
constitution amendment is handled by a separate
`/speckit-constitution` invocation by the maintainer because that
slash-command is the canonical mechanism for amending governance
and bumping the constitution version.

## Per-deliverable plan

### Deliverable 1: Constitution amendment (to be invoked separately)

A `/speckit-constitution` run by the maintainer that:
- Adds a paragraph to Principle I naming quantum adversaries and
  the harvest-now-decrypt-later concern
- Extends the Security & Threat Model section with the PQ posture
- Links to 011-post-quantum-roadmap/research.md as the migration
  plan
- Bumps version 1.0.x → 2.0.0 (MAJOR; redefines an existing
  principle's scope)
- Updates the Sync Impact Report

### Deliverable 2: README roadmap update (in this spec's PR)

The README's Roadmap table grows by 5 rows and one row moves:

| Row change | Before | After |
|---|---|---|
| Insert | — | 011 post-quantum-roadmap |
| Insert (sketched) | — | 012 pq-mixnet-onion-layer |
| Insert (sketched) | — | 013 pq-bls-replacement |
| Insert (sketched) | — | 014 pq-config-chain-redesign |
| Insert (sketched) | — | 015 pq-identity-encryption |
| Move | sketched 011 observability | sketched 016 observability |
| Unchanged | sketched 010 chat-client | sketched 010 chat-client |

The chat-client slot stays at 010 because its position pre-dates
the PQ work and isn't a PQ concern.

### Deliverable 3: spec.md + research.md (in this spec's PR)

Already drafted in this branch. No further work.

### Deferred to per-primitive specs (012–015, not this PR)

- Concrete scheme parameter selection (e.g., ML-KEM-768 vs ML-KEM-
  1024)
- Wire-format versioning byte positions
- JVM library choice (Bouncy Castle vs JNI to liboqs vs others)
- Performance budgets and benchmarks
- Migration timeline per primitive

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

No violations. The proposed constitution amendment is the *point*
of the spec, not a violation of it.
