# Feature Specification: Config Chain Governance

**Feature Branch**: `006-config-chain-governance`

**Created**: 2026-05-20

**Status**: Draft (MVP)

**Input**: Per `011-post-quantum-roadmap` and the README roadmap:
"PKG operations and signed config-chain governance — the social-trust
hinge that controls who is in the mixer/PKG set and how that
membership rotates."

## Why this spec exists

Specs 004 (mixnet-server) and 005 (PKG) ship with a hard-coded
roster of mixers and PKG signers. In production this roster has to
change — new mixers come online, compromised keys are revoked, the
PKG threshold gets re-tuned — and every participant needs to agree
on which version is current. Vuvuzela / Alpenhorn solved this with
a **config chain**: an append-only sequence of *signed* governance
entries that nodes apply in order to update their view of the
system.

Spec 014 already built the cryptographic primitive
(`MultiSignedEntry`): a payload carrying ≥M-of-N ML-DSA-65
signatures verifiable against the current roster + threshold. This
spec puts that primitive into a chain:

- each entry references the previous head by SHA3-256 hash;
- payload semantics declare roster rotation, PKG-key publication,
  epoch markers;
- replay protection comes from the linked head + monotonic epoch.

## User Scenarios & Testing

### User Story 1 — Append a valid governance entry (P1)

A 3-of-5 quorum signs a config entry that publishes a new PKG roster
for epoch N+1. Any participant validates the entry against the
chain's current state and applies it, advancing the chain head.

**Independent Test**: Build a chain at epoch 0 with roster R0
(threshold 3-of-5). Construct a payload promoting two new mixers and
re-issuing the PKG keys for epoch 1. Have 3 of the 5 signers sign;
call `ConfigChain.append`; verify the chain head advances and the
new view reflects the rotation.

**Acceptance Scenarios**:

1. **Given** chain at epoch 0 and a 3-of-5 signed entry chaining
   from the current head, **When** `append` runs, **Then** the head
   advances to the new entry's hash and `currentRoster` reflects
   the rotation.
2. **Given** the same entry but only 2 signatures, **When** `append`
   runs, **Then** the chain rejects with `ThresholdNotMet`.
3. **Given** an entry that does NOT chain from the current head,
   **When** `append` runs, **Then** the chain rejects with
   `WrongPredecessor`.
4. **Given** an entry whose epoch number is not exactly
   `head.epoch + 1`, **When** `append` runs, **Then** the chain
   rejects with `EpochNotMonotonic`.

### User Story 2 — Replay / fork resistance (P1)

A previously applied entry CANNOT be appended again. A fork attempt
(two different entries with the same `prev_hash`) is rejected once
one branch is accepted.

**Independent Test**: After accepting entry E1 (epoch 1), attempting
to apply E1 again returns `AlreadyApplied`. Attempting to apply a
sibling E1' (different payload, same `prev_hash`) returns
`WrongPredecessor` because the head has already moved past
`prev_hash` to E1's hash.

### User Story 3 — Genesis bootstrap (P2)

A fresh chain starts from a genesis entry that names the initial
roster + threshold + epoch 0. The genesis is the only entry whose
`prev_hash` is all-zeros and whose `epoch` is `0`. Genesis is
**self-signed** by its declared roster.

**Independent Test**: `ConfigChain.genesis(roster, threshold, dst)`
returns a chain head pointing at a well-formed genesis entry. The
chain refuses a second genesis.

### Edge Cases

- Roster size must stay ≥ 1; threshold in `[1, roster_size]`.
- Entry payload is opaque except for the four fields the chain
  parses: `epoch`, `prev_hash`, `new_roster`, `new_threshold`. Free
  bytes after that are extension data (006 ignores; future specs
  may extend).
- DST is fixed per chain (e.g., `"siida/config-chain/v1/mainnet"`)
  and supplied at chain construction; entries do NOT carry it on
  the wire.

## Functional Requirements

- **FR-001**: `ConfigChain` MUST validate every `append` against
  the current head + roster + threshold via
  `MultiSignedEntry.verify`.
- **FR-002**: Each entry payload MUST encode (in this order):
  1-byte payload-format version (`0x01`), 8-byte epoch (uint64 BE),
  32-byte prev_hash (SHA3-256 of the parent's wire bytes), 2-byte
  new-roster size `n` (uint16 BE), `n × 1953` PqSignature public
  keys, 2-byte new-threshold (uint16 BE), then opaque extension
  bytes.
- **FR-003**: Genesis entry MUST have `epoch = 0` and
  `prev_hash = 32 × 0x00`. The chain head is therefore
  `SHA3-256(genesis_wire_bytes)` at start.
- **FR-004**: Verification MUST be deterministic — the same inputs
  produce the same accept/reject across architectures.
- **FR-005**: The chain MUST keep an in-memory log of all applied
  entries indexed by epoch. `at(epoch)` returns the historical view.
- **FR-006**: Public API: `genesis`, `append`, `head`, `currentView`,
  `at(epoch)`, `history`.

## Success Criteria

- **SC-001**: A 3-of-5 rotation that replaces 2 signers verifies and
  applies under fixed-seed RNG, in ≤ 100 ms on a developer laptop.
- **SC-002**: Wrong-predecessor, threshold-not-met, epoch-skipped,
  malformed-payload all surface distinct error variants.
- **SC-003**: Replay attempt of an applied entry returns
  `AlreadyApplied` without re-running verification.
- **SC-004**: Genesis-of-genesis (2× genesis) is rejected with
  `GenesisAlreadyEstablished`.

## Out of scope (deferred follow-ups)

- Network distribution / gossip of the chain.
- Persistent storage (the MVP keeps the chain in memory).
- Multi-signer coordination protocols (callers gather sigs out-of-band).
- Anti-equivocation against a malicious quorum (research direction).
- Observability hooks (spec 018).
- Slashing / accountable rotation.

## Constitution check (v2.0.0)

- Principle I (metadata privacy): chain entries are public-by-nature
  (governance metadata is observable to all participants by design);
  no HNDL-sensitive content traverses the chain.
- Principle II (test-first): every error variant covered by tests.
- Principle III (deterministic builds): genesis + entries
  bit-identical across architectures under fixed seed.

## Dependencies

- Spec 013: `siida.crypto.api.PqSignature` (ML-DSA-65 sign/verify).
- Spec 014: `siida.crypto.api.MultiSignedEntry` (threshold sig
  verification).
- JDK 21 SHA3-256 via `java.security.MessageDigest`.
