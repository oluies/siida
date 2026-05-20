# Implementation Plan: Friend Discovery (Add-Request MVP)

**Branch**: `019-friend-discovery` | **Date**: 2026-05-20 | **Spec**: [spec.md](./spec.md)

## Summary

Implement the cryptographic primitive for Alpenhorn-style add-
requests. Alice builds an `AddRequest` ciphertext claiming her
identity + public bundle, encrypted to bob's HybridOnion bundle.
Bob processes, recovers the content, and verifies the claim
against his PKG-directory snapshot. The accepted friend lands in
bob's local `FriendStore`.

Mixnet routing, cover-traffic per round, add-response handshake,
and friendship-key dial tokens are all out-of-scope.

## Technical Context

**Language/Version**: Scala 3.6.4 / JDK 21 LTS (inherited).

**Primary Dependencies**:
- `modules.crypto` — for HybridOnion, Directory, HybridOnion bundles
- (nothing new)

**Storage**: In-memory only (MVP).

**Testing**: munit. Two suites:
- `FriendshipSuite` — build / process / verify happy path,
  impersonation rejection, alg-ID rejection, tamper rejection
- `FriendStoreSuite` — add / lookup / list semantics

**Target Platform**: Linux/amd64, Linux/arm64, Darwin/arm64.

**Performance Goals**: One add-request round-trip under 100 ms.

**Constraints**:
- Verification consults ONLY the directory, never the claimed
  bytes' own self-attestation (SC-006)
- Uniform alg-ID refusal (FR-007)
- API stability per FR-009

**Scale/Scope**:
- 3 new Scala files under `modules/pkg/src/siida/pkg/api/`
- 2 new test files
- Extension to `Errors.scala` for `FriendshipError`

## Constitution Check

### Principle I — Metadata Privacy is Non-Negotiable (v2.0.0)

**Pass.** Friend-discovery IS the metadata-privacy mechanism for
the alice-bob relationship. Once accepted, neither side needs
to consult the PKG on every interaction; the FriendStore is the
local cache.

### Principle II — Spec-Driven, Numbered Feature Workflow

**Pass.** 019 is inserted as a new slot following 018
observability (sketched). README roadmap updates as part of the
PR.

### Principle III — Licence Integrity

**Pass.** No new dependencies.

### Principle IV — Test-First with Deterministic Rounds

**Pass.** Tests use fixed-seed RNG; all flows deterministic.

### Principle V — JVM-Native Mixnet Core

**Pass.** Pure-Java.

### Re-check after Phase 1
**PASS.** No new violations.

## Project Structure

### Documentation (this feature)

```text
specs/019-friend-discovery/
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

### Source Code (additions only)

```text
modules/pkg/src/siida/pkg/api/
├── Errors.scala            # extended with FriendshipError
├── Friendship.scala        # NEW — build/process/verify
├── FriendStore.scala       # NEW — in-memory friend cache
└── AddRequestWire.scala    # NEW — inner-payload codec

modules/pkg/test/src/
├── FriendshipSuite.scala   # NEW
└── FriendStoreSuite.scala  # NEW
```

**Structure Decision**: friend-discovery lives in `modules.pkg`
(same module as identity issuance) because it consumes
PKG-issued bundles + directory snapshots. The SDK (spec 007,
not yet built) will compose `Friendship.buildAddRequest` with
`MixChain.layeredSubmission` for production transport — but
that composition is in `modules.sdk`, not 019.

## Complexity Tracking

| Item | Note | Why not a violation |
|---|---|---|
| FriendStore is mutable | Departs from pure-functional norm | Same trade-off as Pkg's mutable directory state — the store accumulates over time and a follow-up persistent backend can swap in without API change |
| No add-response half | Alpenhorn paper specifies bidirectional | MVP scope; alice → bob direction is enough to demonstrate the primitive. Bob → alice ack lands in a follow-up |
| No friendship-key dial tokens | Alpenhorn optimisation | Local FriendStore cache is enough for the MVP. Dial tokens are a privacy-from-PKG optimization, not a correctness requirement |
| Inline payload codec | Could share `DirectoryEntryWire` from 005 | The payloads are structurally different (no mailbox-id field in friend payloads) so a separate codec is cleaner than an awkwardly-shared one |

## Open coordination items

- **Spec 007 (SDK)**: composes `Friendship.buildAddRequest`
  with `MixChain.layeredSubmission`. The SDK adds cover-add-
  traffic discipline (one add-request per round, real or noise)
  and retry logic.
- **Future add-response spec**: bob sends an acknowledgement
  back to alice through the mixnet, and a half-friendship-key
  for shared-secret derivation. Inverts the alice→bob flow with
  the same primitives.
- **Future friendship-key spec**: PKG-side dial tokens so future
  lookups don't leak identity strings.
- **Future persistent FriendStore spec**: disk-backed storage.

## What 019 explicitly does NOT do

- Does NOT route through the mixnet
- Does NOT provide cover-add-traffic
- Does NOT handle the add-response / acknowledgement half
- Does NOT implement friendship-key dial tokens
- Does NOT persist the FriendStore
- Does NOT handle revocation / unfriend
- Does NOT defend against harassment / block-list
