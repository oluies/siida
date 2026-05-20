# Implementation Plan: PKG Key-Bootstrap

**Branch**: `005-pkg-keybootstrap` | **Date**: 2026-05-20 | **Spec**: [spec.md](./spec.md)

## Summary

Implement the **producer side** of spec 015's directory model.
A `Pkg` holds the roster's ML-DSA-65 private keys, an in-memory
identity table, and a mailbox-id allocator. `issueIdentity`
generates a fresh `HybridSecretBundle`, allocates a mailbox-id,
signs the binding via `MultiSignedEntry` with `threshold` of `N`
roster keys, and adds the entry to the directory.
`directorySnapshot` exposes the state as an
`IdentityEncryption.Directory`.

MVP is in-memory and single-process. Friend-discovery,
persistence, network transport, and roster rotation are
explicitly out-of-scope.

## Technical Context

**Language/Version**: Scala 3.6.4 / JDK 21 LTS (inherited).

**Primary Dependencies**:
- `modules.crypto` — for `HybridOnion`, `PqSignature`,
  `MultiSignedEntry`, `IdentityEncryption` (all on main)
- `modules.mixnet` — for `MixChain.CoverMailboxId` /
  `BroadcastMailboxId` constants

**Storage**: In-memory only (MVP).

**Testing**: munit. Three suites:
- `PkgSuite` — issuance, duplicate detection, mailbox allocation,
  determinism
- `DirectorySnapshotSuite` — snapshot composes with 015's
  `IdentityEncryption.encrypt` / `decrypt` end-to-end
- `PkgErrorsSuite` — configuration validation (empty roster,
  bad threshold)

**Target Platform**: Linux/amd64, Linux/arm64, Darwin/arm64.
Pure-Java.

**Performance Goals** (sanity bounds, MVP):
- One `issueIdentity` under 100 ms (dominated by HybridOnion
  keygen + N ML-DSA-65 signatures, threshold typically 3-5)

**Constraints**:
- `Pkg` does NOT retain issued secret bundles
- Mailbox allocation skips reserved IDs (0, -1)
- API stability per FR-008 once merged

**Scale/Scope**:
- 4 new Scala files under `modules/pkg/src/`
- 3 new test files under `modules/pkg/test/src/`
- 2 new `moduleDeps` entries (crypto + mixnet)

## Constitution Check

### Principle I — Metadata Privacy is Non-Negotiable (v2.0.0)

**Pass.** The PKG is the trust anchor; metadata privacy
considerations (PKG sees lookup patterns) are documented in
015's threat-model.md and mitigated by SDK-level anonymous
routing (spec 007).

### Principle II — Spec-Driven, Numbered Feature Workflow

**Pass.** 005's slot was reserved in 001's roadmap.

### Principle III — Licence Integrity

**Pass.** No new dependencies; everything via existing modules.

### Principle IV — Test-First with Deterministic Rounds

**Pass.** Issuance is deterministic given fixed-seed RNG (FR-009).

### Principle V — JVM-Native Mixnet Core

**Pass.** Pure-Java; no JNI.

### Re-check after Phase 1
**PASS.** No new violations.

## Project Structure

### Documentation (this feature)

```text
specs/005-pkg-keybootstrap/
├── plan.md
├── spec.md
├── research.md
├── contracts/
│   ├── scala-api.md
│   └── wire-format.md
├── checklists/
│   └── requirements.md
└── tasks.md
```

### Source Code

```text
modules/pkg/
├── src/
│   └── siida/pkg/api/
│       ├── Pkg.scala                   # core PKG state + issueIdentity
│       ├── IssuedIdentity.scala        # return type
│       ├── Errors.scala                # PkgError enum
│       └── DirectoryEntryWire.scala    # payload codec for FR-006
└── test/
    └── src/
        ├── PkgSuite.scala
        ├── DirectorySnapshotSuite.scala
        └── PkgErrorsSuite.scala
```

`build.mill`: `modules.pkg` declares
`moduleDeps = Seq(modules.crypto, modules.mixnet)`.

**Structure Decision**: PKG state is mutable (the directory grows
as identities are issued). Implemented as a class with private
mutable state, not a pure-functional Pkg. The trade-off: a
follow-up spec can swap the storage for a persistent backend
without changing the API. Tests use a fresh `Pkg` instance per
test for isolation.

## Complexity Tracking

| Item | Note | Why not a violation |
|---|---|---|
| Mutable state in `Pkg` | Departs from pure-functional norm | The PKG state is naturally stateful — identities accumulate. Pure-functional state-monad shape would be more complex without operational benefit at MVP scale. |
| Threshold signatures use signers `[0, M)` | Fixed signer selection | MVP keeps the selection simple; policy-driven signer choice is a follow-up |
| No friend-discovery | Roadmap entry mentions it | Friend discovery is a non-trivial sub-protocol (Alpenhorn's add-request flow with mixnet integration); folding it into 005 would balloon scope |

## Open coordination items

- **Spec 006 (config-chain)**: rotates the PKG roster. 005's
  `Pkg` takes the roster as construction-time configuration; a
  follow-up spec adds `Pkg.rotateRoster(newRoster, proof)`.
- **Spec 007 (SDK)**: caches directory snapshots, routes
  lookups via the mixnet. 005 provides the `directorySnapshot`
  pull point; the SDK decides when and how to refresh.
- **Spec 008 (agent-messaging)**: defines the identity-string
  format for agents. 005 stores bytes, not UTF-8; the format is
  a higher-layer convention.
- **Spec 009 (async-delivery)**: consumes mailbox-ids issued by
  this PKG.

## What 005 explicitly does NOT do

- Does NOT implement friend-discovery
- Does NOT persist state across PKG restarts
- Does NOT define a network protocol
- Does NOT enforce identity-ownership policy
- Does NOT support roster rotation
- Does NOT provide Bloom-filter / incremental directory fetches
- Does NOT provide operator tooling
