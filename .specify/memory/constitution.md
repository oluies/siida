<!--
Sync Impact Report
==================
Version change: 1.0.0 → 2.0.0
Bump rationale: MAJOR — the constitution's own versioning rules name
"a change to the adversary model" as one of the explicit MAJOR
triggers. This amendment adds quantum adversaries (including the
harvest-now-decrypt-later capability) to Principle I's scope and
extends the Security & Threat Model section with the post-quantum
posture and a pointer to the migration roadmap.

Modified principles:
  - I. Metadata Privacy is Non-Negotiable
        (kept title; expanded to include quantum-adversary scope and
        the HNDL concern; explicit linkage to the 011-post-quantum-
        roadmap migration plan; classical primitives remain in
        service pending per-primitive replacement specs 012–015)

Modified sections:
  - Security & Threat Model — added post-quantum posture bullet and
    a "classical-era specs" note so 001-003 are not retroactively
    non-compliant

Added sections: none
Removed sections: none

Templates requiring updates:
  - .specify/templates/plan-template.md      ✅ no edit needed — Constitution Check is per-feature; the v2.0.0 clauses are picked up automatically by future plans
  - .specify/templates/spec-template.md      ✅ no edit needed — principle-agnostic structure
  - .specify/templates/tasks-template.md     ✅ no edit needed — generic task categorisation
  - README.md                                ✅ already updated by 011 — roadmap shows 011–015 (PQ migration slots)
  - specs/001-project-bootstrap, specs/002-crypto-pairing, specs/003-dependency-automation
                                             ✅ NOT retroactively amended — explicit "classical-era specs" carve-out in the new Security & Threat Model bullet

Follow-up TODOs: none

Predecessor: v1.0.0 ratified on 2026-05-16; this is the first
amendment.
-->

# Siida Constitution

## Core Principles

### I. Metadata Privacy is Non-Negotiable

Siida exists to keep *who is talking to whom* private against a global passive
adversary who can observe every packet on every link, **AND against a
quantum-capable adversary that may collect ciphertext today for later
decryption** (the harvest-now-decrypt-later threat). Every design decision
MUST preserve these guarantees end-to-end:

- All client-to-mixnet traffic MUST be onion-encrypted with NaCl `box` (or a
  vetted replacement) and submitted in lockstep rounds, with cover traffic
  when the user has nothing to say.
- Mixers MUST strip exactly one layer and shuffle the entire batch before
  forwarding; partial-batch forwarding is forbidden.
- Mixers MUST inject differentially-private dummy traffic calibrated to a
  documented epsilon; the parameters live in the spec for whichever feature
  introduces or modifies them.
- No feature may add a side channel — log line, metric label, retry path,
  error response, or persisted record — that leaks per-user round
  participation, recipient identity, message size beyond the fixed cell,
  or timing relative to round boundaries.
- The boundary is explicit: NATS, dtn7-style stores, and any non-mixnet
  transport are permitted ONLY at the agent ingress boundary and the async
  delivery substrate; they MUST NOT carry round-aligned mix traffic.
- **Quantum adversaries are in scope from 2026-05-19.** A quantum adversary
  with HNDL capability — storing ciphertext now to decrypt when a
  sufficiently large quantum computer becomes available — MUST be considered
  for every cryptographic primitive Siida ships. HNDL needs no quantum
  capability *at the time of ciphertext capture*; only later. This makes
  every pre-quantum ciphertext leaving the network today a future-decrypted
  ciphertext under conservative assumptions.
- **Classical primitives remain in service during the migration window.**
  BN254 pairings (002), Boneh-Franklin IBE (002), BLS over BN254 (002), and
  NaCl `box` over x25519 (mixnet onion layers) continue to ship pending the
  per-primitive replacement specs 012-pq-mixnet-onion-layer through
  015-pq-identity-encryption tracked in
  [011-post-quantum-roadmap/research.md](../../specs/011-post-quantum-roadmap/research.md).
  Once each replacement spec lands, the corresponding primitive MUST be
  removed from this list and this principle MUST be amended to record the
  cutover. The roadmap commits to hybrid (classical + PQ) handshakes during
  migration; the per-primitive specs choose the combiner construction per
  011's research R5.

**Rationale**: Vuvuzela's contribution is metadata privacy under a strong
adversary model; weakening it makes Siida a worse version of a system that
already exists. The original Vuvuzela threat model assumed a classical
adversary; Siida v2.0.0 makes the quantum extension explicit because every
month of pre-PQ ciphertext we ship is a month of HNDL exposure that the
v1.0.0 threat model was silent on. Any deviation MUST be justified in
writing in the feature spec and approved per the Governance section.

### II. Spec-Driven, Numbered Feature Workflow

All non-trivial work — new features, protocol changes, dependency swaps,
cryptographic primitives, observability additions — MUST flow through
`/speckit-*` commands:

- Each feature lives in `specs/NNN-name/` with `spec.md`, `plan.md`, and
  `tasks.md`. The number is monotonically increasing; no reuse, no gaps
  beyond what the roadmap records.
- Specs are authored before implementation. `spec.md` MUST be approved (or
  explicitly clarified via `/speckit-clarify`) before `plan.md` is
  generated; `plan.md` MUST exist before `tasks.md`; `tasks.md` MUST exist
  before implementation begins under `/speckit-implement`.
- The current roadmap (000–009 implemented + sketched 010 chat-client,
  011 post-quantum-roadmap landed, 012–015 PQ per-primitive migrations
  sketched, 016 observability sketched) is the authoritative order.
  Re-ordering MUST be recorded as a constitution amendment if it changes
  which spec gates which.
- Trivial fixes (typos, dependency security bumps, build hygiene) MAY bypass
  the full spec flow but MUST be committed with a message stating why no
  spec was required.

**Rationale**: Specs preserve intent across migrations between contributors,
agents, and time. They are the only durable record of *why* a privacy- or
crypto-relevant decision was made.

### III. Licence Integrity (AGPL-3.0-or-later Compatible Only)

Siida is a derivative work of Vuvuzela and Alpenhorn and inherits their
AGPL-3.0-or-later licence. Every dependency, every snippet, every imported
runtime MUST be compatible:

- New runtime/library dependencies MUST be one of: AGPL-3.0-or-later, GPL-3.0,
  LGPL-3.0, Apache-2.0, BSD (2-/3-clause), MIT, MPL-2.0, or ISC. Other
  licences require an amendment to this constitution.
- Lightbend BSL-licensed Akka 2.7+ is FORBIDDEN. Apache Pekko (the
  Apache-2.0 fork of Akka 2.6.x) is the only Akka-family runtime permitted.
- Files inheriting permissive headers from upstream (Go `bn256`, dclxvi,
  etc.) MUST retain the original BSD-3-clause header at file scope. `NOTICE`
  MUST be updated whenever a new upstream lineage is introduced.
- Cryptographic primitives MUST come from actively maintained sources; the
  current target replacement for dclxvi is `consensys/gnark-crypto/ecc/bn254`
  reached via JNI or a pure-Scala port, as decided in feature `002`.
- PQ primitives introduced by the 012–015 migration specs MUST follow the
  same licence policy. NIST/BSI-aligned reference implementations are
  typically Apache-2.0 or MIT (Bouncy Castle PQ providers MIT, liboqs MIT,
  open-quantum-safe lattice implementations Apache-2.0); per-spec licence
  review still applies.

**Rationale**: Vuvuzela's AGPL is the licence that lets Siida exist; a
single incompatible dependency makes the whole project unredistributable.

### IV. Test-First with Deterministic Rounds (NON-NEGOTIABLE)

Tests MUST be written, reviewed, and observed failing before the
implementation that makes them pass:

- Red-Green-Refactor is mandatory for all mixnet-core, crypto, and protocol
  code (everything below the ingress boundary).
- Round-driven components — coordinator, mixer shuffle, onionbox, batch
  processing, async delivery convergence — MUST be testable in deterministic
  mode: simulated clock, fixed RNG seed, and reproducible round outcomes.
  PRs MUST NOT introduce flaky tests guarded by retries or sleeps.
- Integration tests are required for: new library contracts, wire-format
  changes, inter-service messages, shared schemas, and any change that
  crosses the privacy-sensitive / ingress boundary.
- Client SDK code MAY use property-based tests in addition to example tests
  for serialisation, retransmission, and config-chain verification paths.
- Test code MUST NOT log or persist anything that real production code is
  forbidden from logging or persisting (see Principle I).

**Rationale**: A mixnet is correct only if its rounds are correct, and rounds
are correct only if they are reproducible. Without determinism, regressions
in the privacy guarantee are invisible.

### V. JVM-Native Mixnet Core (Scala 3 + Pekko + Cats Effect 3)

The mixnet core — coordinator, mixers, PKG, client SDK — MUST be implemented
in Scala 3 on the JVM:

- Concurrency is expressed through Cats Effect 3 fibers and Pekko Streams /
  Pekko Cluster. Raw `Thread`, blocking `Future` chains, and unstructured
  `Promise` use are forbidden in the mixnet core.
- Pekko Persistence is the persistence model for round-durability state.
- HTTP, where needed, is `http4s`; serialisation defaults to scodec or
  protobuf, chosen per-feature in `plan.md`.
- The build MUST run, test, and produce identical artefacts on every
  architecture Pekko supports, explicitly including Apple Silicon (no cgo,
  no x86-64-only assembly in the JVM core). Native code reached over JNI
  (e.g., gnark-crypto) MUST ship pre-built binaries or build hermetically
  for every supported architecture; otherwise a pure-Scala fallback MUST
  exist.
- The build tool is **Mill**. Rationale: smaller dependency surface (easier
  AGPL provenance audit), Scala-as-code task graphs that scale to the
  multi-artefact builds expected in features 002 (JNI / pure-Scala BN254
  flavours) and 009 (async-delivery convergence-layer JAR), and faster
  cold-start than sbt for the round-deterministic test harnesses required
  by Principle IV. Changing the build tool requires a constitution
  amendment.
- Non-JVM components are permitted ONLY outside the mixnet core: ingress
  adapters (gRPC, NATS, typed sockets), DTN bundle stores (`dtn7-rs`),
  build/ops tooling, and future multi-language client SDKs.

**Rationale**: A single language and runtime in the privacy-critical core
keeps the audit surface small. Pekko is the only Akka-family runtime
licence-compatible with AGPL Siida (see Principle III), and Cats Effect 3
gives the typed-fibre concurrency model the SDK requires.

## Security & Threat Model

- **Adversary model**: a global passive adversary observing every link, plus
  active compromise of a strict minority of mixers, **plus a quantum-capable
  adversary with harvest-now-decrypt-later capability** (per Principle I).
  Active compromise of the PKG is partially mitigated by Alpenhorn-style
  key bootstrap.
- **Trust boundary**: the JVM mixnet core is trusted; everything reached
  through the ingress boundary or the async-delivery substrate is untrusted
  and MUST be validated against the same wire schemas as untrusted clients.
- **Cryptographic agility**: pairing curves, AEAD choices, and hash
  functions are pinned per feature spec. Migrations (e.g., dclxvi → bn254;
  classical → PQ) are themselves feature specs and MUST include a
  deprecation window and a documented compatibility break.
- **No telemetry leaks**: OpenTelemetry, structured logging, and metrics
  MUST NOT carry user identifiers, recipient identifiers, per-round
  participation flags, or message content. Aggregate counters bucketed at
  the round level are permitted.
- **Reproducible builds**: release artefacts SHOULD be reproducible bit-for-bit
  from tagged source on a documented toolchain; deviations require an issue
  with a remediation plan.
- **Post-quantum posture (effective 2026-05-19)**: per-primitive PQ
  replacement is staged through specs 012-pq-mixnet-onion-layer,
  013-pq-bls-replacement, 014-pq-config-chain-redesign, and
  015-pq-identity-encryption — the four slots reserved by
  011-post-quantum-roadmap. Scheme choices anchor to BSI TR-02102-1 with
  ANSSI / ENISA as secondary tracking; Swedish-affiliated research
  provenance (Lund University, KTH, RISE) is a soft tie-breaker when
  multiple schemes are otherwise equivalent. See
  [011-post-quantum-roadmap/research.md](../../specs/011-post-quantum-roadmap/research.md)
  for the full per-primitive table and the hybrid handshake combiner.
- **Classical-era specs**: 001-project-bootstrap, 002-crypto-pairing, and
  003-dependency-automation were ratified under constitution v1.0.0 and
  shipped pre-quantum primitives. They are NOT retroactively non-compliant.
  The 011 roadmap (and the per-primitive 012–015 specs it spawns) is the
  remediation path. No Constitution Check is re-opened against them; the
  cutover happens per primitive when each migration spec lands.

## Development Workflow & Quality Gates

- **Dual CI**: GitHub Actions is canonical for now; a mirror Forgejo Actions
  workflow MUST stay green so a move to Codeberg is a copy-and-push. A PR
  that passes GitHub but breaks the Forgejo mirror is NOT mergeable.
- **Branch naming**: feature work uses Spec Kit's conventions (numbered
  feature branches such as `001-project-bootstrap`). Long-running task
  branches use the `task/` prefix; throwaway worktrees use `.worktrees/`.
- **PR review**: every PR MUST link to the spec it implements (or justify
  bypass per Principle II) and MUST pass: build, test (including the
  deterministic-round tests for any touched core), formatter, linter,
  licence-header check, and the Forgejo mirror.
- **Commit hygiene**: no `--no-verify`, no `--amend` of pushed commits, no
  force-push to `main`. Hook failures are root-caused, not skipped.
- **Complexity tracking**: features that introduce a 4th project, a
  repository pattern, a new persistence layer, or a new runtime fill in
  `plan.md`'s Complexity Tracking table with the rejected simpler
  alternative.
- **Spec Kit hooks**: the hooks in `.specify/extensions.yml` (auto-commit
  after each phase, mandatory git init before constitution) are part of the
  workflow contract; disabling a hook requires an amendment.

## Governance

This constitution supersedes ad-hoc practice. Where it conflicts with a
README, a comment, or a chat agreement, the constitution wins until amended.

- **Authority**: amendments are made by a PR that edits this file, increments
  the version line per the rules below, and updates the Sync Impact Report
  at the top.
- **Versioning policy** (semantic):
  - **MAJOR**: removal or backward-incompatible redefinition of a principle,
    a change to the adversary model, a change of permitted licences, or any
    edit that invalidates a previously-shipped spec's Constitution Check.
  - **MINOR**: a new principle or section, materially expanded guidance, or
    a new mandatory quality gate.
  - **PATCH**: clarifications, wording, typo fixes, non-semantic refinements
    that do not change what is required.
- **Approval**: amendments require at least one reviewer who did not author
  the change. Privacy-relevant amendments (anything touching Principle I or
  the Security & Threat Model section) require an explicit `privacy-review`
  label and a written rationale in the PR description.
- **Compliance review**: every `/speckit-plan` Constitution Check MUST map
  the feature's plan to each numbered principle. Violations are recorded in
  the plan's Complexity Tracking table or block the merge.
- **Runtime guidance**: developer-facing runtime guidance lives in
  `README.md`, `CLAUDE.md`, and per-feature `quickstart.md` files; those
  documents MUST be updated when an amendment changes their preconditions.

**Version**: 2.0.0 | **Ratified**: 2026-05-16 | **Last Amended**: 2026-05-19
