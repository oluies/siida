# Feature Specification: PQ Config-Chain Redesign (Per-Signer ML-DSA + Batch Verify)

**Feature Branch**: `014-pq-config-chain-redesign`

**Created**: 2026-05-20

**Status**: Draft — design spec; spec 006 implements

**Input**: Per 011-post-quantum-roadmap research.md row 3: redesign
the config chain to not depend on BLS aggregate signatures. Without
aggregation, per-signer ML-DSA signatures (013) are stored
individually and verified together via `PqSignature.batchVerify`.

## Why this spec exists

The Vuvuzela-derived config chain (slated for implementation in spec
006-config-chain-governance) used BLS signature aggregation to
compress an M-of-N multi-signer attestation into a single ~64-byte
aggregate. Spec 013-pq-bls-replacement removed aggregation as the
unavoidable cost of moving to ML-DSA-65 (no production-grade PQ
aggregate signature exists). The config chain now needs a different
shape.

014 designs that shape **before** 006 is written, so 006 can be
authored against a PQ-clean foundation rather than retrofitted.

The redesign trades storage for security: an M-of-N entry now
carries N (signer_index, signature) tuples instead of one aggregated
signature. With ML-DSA-65 (3294-byte signatures from 013) and a
realistic N = 8, an entry is ~26 KB of signatures plus the entry
payload itself. Acceptable because config updates are infrequent
(governance traffic, not round-aligned).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A config-chain entry is signed by N distinct signers and verified by batchVerify (Priority: P1)

The 006 spec consumes this: a config entry's payload (epoch number,
new mixer set, new PKG master public bundle, etc.) is signed by N
distinct members of the current roster, each producing an
independent ML-DSA-65 signature. Verifiers use
`PqSignature.batchVerify` from 013 to check all N signatures in a
single batched call, then count distinct successful signers
against the threshold M.

**Why this priority**: P1 because this is the load-bearing shape
change — every consumer of config-chain entries (clients
bootstrapping, mixers checking peer rosters, agents validating
identity proofs) depends on the verifier knowing how to read
multi-signer entries.

**Independent Test**: Construct an entry with payload P signed by
3-of-5 roster members, all under valid keys; verify it accepts.
Construct the same entry with only 2 valid signatures (1 forged or
missing); verify it rejects with a clear threshold-not-met error.

**Acceptance Scenarios**:

1. **Given** a roster of N=5 valid public keys, an entry payload
   P, and 3 valid signatures from members [0, 2, 4],
   **When** the verifier checks against threshold M=3,
   **Then** the entry is accepted.
2. **Given** the same setup but with member [4]'s signature
   tampered, **When** the verifier checks against M=3,
   **Then** the entry is rejected with `ThresholdNotMet`
   (2 valid < 3 required).
3. **Given** an entry with two signatures from the same signer
   (member [0] signs twice), **When** verified,
   **Then** the entry is rejected with `DuplicateSigner` (each
   slot counts once regardless of how many sigs that signer
   contributed).
4. **Given** an entry with a signature whose signer_index is out
   of range (e.g., index 99 with a 5-member roster),
   **When** verified, **Then** the entry is rejected with
   `InvalidSignerIndex`.

### User Story 2 - Threshold semantics: an entry is valid iff at least M-of-N distinct signers verify (Priority: P1)

The threshold M and roster size N are properties of the chain
configuration, set per chain instance. Spec 006 reads them from a
preceding entry (the "roster epoch" entry) or from the genesis
entry. 014 just defines the verification predicate: count distinct
signers whose signatures pass `batchVerify`; accept iff count ≥ M.

**Why this priority**: P1 because threshold semantics is the
trust-model core. M=1 reduces to a single-signer chain (no
multi-party governance); M=N gives unanimous-approval (rigid); M
≈ 2N/3 is the typical practical choice (Byzantine-fault-tolerance
oriented).

**Independent Test**: Construct entries at various (M, N) combinations
and confirm the verification predicate matches expectation.

### User Story 3 - Wire format for a multi-signer entry is committed and stable (Priority: P2)

A config-entry on the wire carries:
- payload bytes (opaque to 014; spec 006 defines payload shape)
- 1-byte version tag (allows future entry-format bumps)
- 1-byte signature count `n`
- `n` × `(2-byte signer_index, 3294-byte ML-DSA-65 signature)`
  tuples = ~26 KB per 8-signer entry
- 32-byte SHA3-256 hash of the payload, included in what each
  signer signs (so verification doesn't require the verifier to
  serialise the payload identically — it just hashes once and
  compares)

**Why this priority**: P2 because storage layout is operational
overhead; correctness depends on US1 + US2. Pinning it here means
spec 006 doesn't relitigate the format.

**Independent Test**: A reference encoder/decoder round-trips an
entry through the wire format; a reference verifier reads the
wire format and applies the US1/US2 predicate.

### Edge Cases

- **Reordered signatures in wire format**: the verifier MUST NOT
  depend on signer-index ordering — sort by index internally before
  batch-verifying. Replay/canonicality concerns are 006's job.
- **Duplicate signer_index in the same entry**: rejected with
  `DuplicateSigner`. An entry with the same signer providing two
  signatures counts the signer once at most; if both sigs are
  valid, accept the entry but count the signer once toward the
  threshold. Practical choice: reject outright because the
  duplication is either an authoring bug or a tampering attempt.
- **Signer-index points at a vacated slot**: 006's roster epoch
  defines which indices are populated; verifier rejects with
  `InvalidSignerIndex` if the index isn't in the active set.
- **Mismatched payload hash**: an entry where the signed payload-hash
  doesn't match the actual payload (someone tampered with payload
  AFTER signing): rejected with `PayloadHashMismatch`.
- **Empty signature list (n=0)**: rejected with `ThresholdNotMet`
  regardless of M.
- **Quantum-adversary scope**: same as 013. No HNDL concern for
  signatures (signatures are public); the risk is signature
  forgery once a quantum computer exists. ML-DSA-65 mitigates.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The crypto module MUST expose
  `siida.crypto.api.MultiSignedEntry` with `verify(roster: Seq[PqPublicKey],
  threshold: Int, payloadHash: Array[Byte], entry: MultiSignedEntry):
  VerifyResult`. The result is one of: `Valid`,
  `ThresholdNotMet(validCount: Int, required: Int)`,
  `DuplicateSigner(index: Int)`, `InvalidSignerIndex(index: Int)`,
  `PayloadHashMismatch`, `MalformedEntry(reason: String)`.
- **FR-002**: The underlying signature primitive MUST be
  `PqSignature` (ML-DSA-65) from spec 013. No direct dependency on
  Bouncy Castle in 014's code; everything flows through 013's
  public API.
- **FR-003**: `verify` MUST use `PqSignature.batchVerify` to
  validate all signatures in a single batched call.
- **FR-004**: The wire format MUST be self-versioning via a leading
  1-byte version tag; the value `0x01` identifies the format in
  this spec. Future format-bumps get `0x02+`.
- **FR-005**: `verify` MUST be tolerant of signer-list ordering
  (sort by signer_index before batching). It MUST be intolerant of
  duplicate signer_index (reject with `DuplicateSigner`).
- **FR-006**: Each signer signs the SHA3-256 hash of the payload
  bytes, not the payload itself. The hash MUST be 32 bytes; the
  signed message presented to ML-DSA is the hash concatenated with
  a per-chain domain-separation tag (so signatures from one chain
  don't replay into another).
- **FR-007**: The empty signature list MUST be treated as failing
  the threshold check (`ThresholdNotMet(0, M)`).
- **FR-008**: Test fixtures MUST be deterministic (fixed-seed
  pattern from 002/012/013).
- **FR-009**: The wire format MUST be documented in
  `contracts/wire-format.md` and locked once 014 merges (FR-010
  stability discipline).
- **FR-010**: The public Scala API surface MUST be stable post-014
  merge per the same FR-010 pattern as 002 / 012 / 013.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An 8-signer 3-of-8 entry verifies in under 100 ms on
  a typical developer laptop (driven by `batchVerify` cost: 8
  ML-DSA sigs at ~0.6n = ~5 verifications worth of work).
- **SC-002**: Wire-format size for an 8-signer entry is
  approximately `1 + 1 + 8 × (2 + 3294) + 32 ≈ 26,402 bytes` plus
  the payload itself. Documented in `contracts/wire-format.md`.
- **SC-003**: Every edge-case path from the spec (US1 acceptance
  scenarios 1-4, threshold variations, duplicate signer, invalid
  index, hash mismatch, empty list) has a deterministic test
  fixture.
- **SC-004**: Spec 006-config-chain-governance, when authored, can
  consume `MultiSignedEntry` without amending its wire format or
  verification semantics. (Verified by review when 006 lands.)

## Assumptions

- Constitution v2.0.0 holds; quantum adversaries in scope.
- Spec 013 ships first; `PqSignature` is available.
- Threshold M and roster size N are properties of the chain
  configuration, set by 006 not 014. 014 only defines the
  verification predicate parameterized on (M, roster).
- 26 KB per 8-signer entry is acceptable. Config-chain entries
  are infrequent (governance, not round-aligned). If real-world
  governance traffic outgrows the storage budget, a future spec
  may explore PQ multisignature schemes (research-stage as of
  2026-05).
- The per-chain domain-separation tag (FR-006) is set by 006;
  014 just requires that it be included in the signed-message
  derivation.
- Per-signer identity → roster index mapping is a 006 concern;
  014 treats signer_index as an opaque 16-bit value.
- No hybrid (classical BLS + PQ ML-DSA) signing per chain entry.
  Per 013 research R4, hybrid signatures don't add value over
  PQ-only.
