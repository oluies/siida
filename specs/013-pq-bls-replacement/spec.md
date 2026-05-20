# Feature Specification: PQ BLS Replacement (ML-DSA-65)

**Feature Branch**: `013-pq-bls-replacement`

**Created**: 2026-05-20

**Status**: Draft

**Input**: Per 011-post-quantum-roadmap research.md row 2: replace
single BLS signatures (BN254-based) with ML-DSA-65 (FIPS 204). Lose
the BLS aggregation property — distinct-message and same-message
aggregation are out; batch verification (CPU-savings only) is the
production fallback.

## Why this spec exists

Spec 002 shipped BLS signatures over BN254 — sign / verify / aggregate
with proofs-of-possession. Used by mixer attestations (004) and the
config chain (006). Under constitution v2.0.0, the BN254-pairing
security assumption (co-CDH) is broken by Shor's algorithm. A
quantum-capable adversary CAN forge BLS signatures by recovering
private keys from public keys.

Signatures are public-by-nature so harvest-now-decrypt-later doesn't
apply (no plaintext to retroactively recover). The risk is *forgery*
once Shor exists. The migration timing is therefore "ship PQ
signatures before a sufficiently large quantum computer exists,"
which is more forgiving than 012's HNDL-driven migration of onion
layers — but the migration itself is harder because **PQ signatures
do not aggregate** in any production-grade way.

Per 011 research R2 and R3, the chosen replacement is **ML-DSA-65**
(FIPS 204), used as single signatures. The 014-config-chain-redesign
spec handles the aggregation-loss consequence.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Single PQ signature: sign / verify works on ML-DSA-65 (Priority: P1)

A signer (mixer issuing an attestation, PKG signing a config update,
or a future agent identity proof) produces a signature that verifies
under the corresponding public key, and forgery is computationally
infeasible against a quantum-capable adversary.

**Why this priority**: P1 because every consumer of signatures
(configchain 006, mixer attestations in 004, agent identity in 008)
depends on this primitive existing in PQ form. Without 013, the
relevant components ship with BN254 BLS and remain forgery-vulnerable
once Shor is real.

**Independent Test**: A test fixture (a) generates an ML-DSA-65 key
pair; (b) signs a known message; (c) verifies under the matching
public key — succeeds; (d) verifies under a different public key —
fails; (e) verifies a tampered message — fails. Cross-arch
deterministic.

**Acceptance Scenarios**:

1. **Given** an ML-DSA-65 keypair and a message, **When** the
   signer calls `PqSignature.sign(sk, msg)` and the verifier calls
   `PqSignature.verify(pk, msg, sig)`, **Then** verification returns
   `true`.
2. **Given** the same signature and a *different* public key,
   **Then** verification returns `false` (NOT an exception).
3. **Given** the same signature and a tampered message,
   **Then** verification returns `false`.
4. **Given** fixed-seed RNG, **When** sign runs on Linux/amd64 and
   macOS/arm64, **Then** the produced signature bytes are
   bit-identical across architectures.

### User Story 2 - Aggregation is removed from the public API (Priority: P1)

The existing `BLS.aggregate` and `BLS.verifyAggregate` /
`BLS.verifyAggregateDistinct` methods on the classical primitive
remain available for the BN254 path but the **new** `PqSignature`
API does NOT provide aggregation. Callers that need many-signer
attestations use batch verification (US3) or the config-chain
redesign in 014.

**Why this priority**: P1 because the absence of aggregation is the
load-bearing semantic change of this spec. Surfacing it explicitly
in the API (rather than via a stub-that-throws like 012's pattern)
makes the cost-of-PQ-migration legible to callers.

**Independent Test**: Inspect the `siida.crypto.api.PqSignature`
object; confirm there is no `aggregate` method. The contract is
"sign one, verify one"; no batched aggregation exists.

### User Story 3 - Batch verification: many signatures verified faster than the sequential equivalent (Priority: P2)

A verifier with `n` (pk, msg, sig) tuples MAY use
`PqSignature.batchVerify` to validate them all in a single operation.
Returns `true` iff every tuple verifies. CPU cost is sub-linear
(typically ~0.6n verifications worth of work for n = 8-16); no
signature-size savings.

**Why this priority**: P2 because functional correctness depends on
US1; batching is a performance optimization the config-chain (006)
will benefit from when checking N signers' approvals on a config
update.

**Independent Test**: A fixture verifies 8 valid (pk, msg, sig)
tuples via `batchVerify` and confirms the result is `true`; replacing
any one tuple with a forgery flips the result to `false`.

### Edge Cases

- **Mixed-message batch**: `batchVerify` accepts tuples with arbitrary
  messages (each tuple is `(pk, msg, sig)` independent). Same-message
  batching has no efficiency advantage in ML-DSA's batch construction.
- **Empty batch**: `batchVerify([])` returns `false` (the empty
  product is trivially true but the caller almost certainly meant
  something else).
- **Tampered signature in batch**: `batchVerify` returns `false`
  without revealing WHICH tuple failed (uniform error; no side
  channel about which signer's signature is bad).
- **Wire-format alg-ID byte**: every PQ signature on the wire carries
  algorithm ID `0x10` (reserved space distinct from 012's onion-layer
  IDs). Future PQ-only signature variants get `0x11+`.
- **PoP-equivalent**: the BLS proof-of-possession primitive was a
  rogue-key defence for aggregation; without aggregation it's
  unnecessary in 013's API. (Per-key PoPs may still appear in 014's
  config-chain design for a different purpose; not this spec's
  concern.)
- **Hybrid signatures (classical BLS + PQ)**: NOT in 013's scope.
  Per 011 research R6 and BSI/ENISA guidance, signature schemes do
  not combine usefully (max of two sig sizes, both verifications
  costly); the migration is a hard PQ-only cutover when the
  consuming spec ships a PQ-only release.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The crypto module MUST expose `siida.crypto.api.PqSignature`
  with `sign(sk, message): Signature`, `verify(pk, message, sig): Boolean`,
  and `batchVerify(tuples: Seq[(pk, msg, sig)]): Boolean`.
- **FR-002**: The underlying signature scheme MUST be ML-DSA-65
  (FIPS 204). No SLH-DSA fallback in this spec (archival
  signatures are a future spec if needed).
- **FR-003**: Signature wire format MUST carry algorithm ID `0x10`
  as its FIRST byte; the remaining bytes are the ML-DSA-65 signature
  (3293 bytes for parameter set 3). Total: 3294 bytes.
- **FR-004**: Public key wire format MUST be the raw ML-DSA-65
  encoded public key (1952 bytes) preceded by 1-byte algorithm ID
  `0x10`. Total: 1953 bytes.
- **FR-005**: `verify` and `batchVerify` MUST return `false` (NOT
  throw) on any failure: wrong key, tampered message, malformed
  signature bytes, unsupported algorithm ID. Programming errors
  (wrong-length buffers crossing the FFI) still throw.
- **FR-006**: `batchVerify([])` MUST return `false`.
- **FR-007**: The existing classical `siida.crypto.api.BLS` object
  remains in service for the classical-era specs (002 tests, etc.)
  but MUST be annotated `@deprecated("Use PqSignature for new
  code; BLS over BN254 is quantum-vulnerable per constitution v2.0.0
  Principle I", "v2.0.0")`. Tests and downstream code currently using
  it produce a deprecation warning but still compile.
- **FR-008**: Test fixtures MUST be deterministic under fixed-seed
  RNG (FR matches 012's pattern).
- **FR-009**: Test KAT vectors MUST pin one ML-DSA-65 signature for
  a documented (sk_seed, message) pair. Same self-referential KAT
  shape as 002/012; external NIST CAVS vectors are a deferred
  follow-up.
- **FR-010**: The public Scala API surface MUST be locked once 013
  merges — no rename or signature change without a follow-up spec
  (same FR-010 pattern as 002 and 012).
- **FR-011**: The implementation MUST use Bouncy Castle's ML-DSA
  (Dilithium) provider — no Siida-original lattice implementation.
  Same library choice as 012 (BC's PQ provider is pure-Java; no
  per-arch matrix needed).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of ML-DSA-65 KAT vectors (FR-009) pass on every
  CI run on both supported architectures.
- **SC-002**: The sign/verify round-trip in `PqSignatureSuite`
  passes; the forgery-resistance negative tests (wrong key,
  tampered message) also pass.
- **SC-003**: `batchVerify(8 valid tuples)` returns `true` and
  measurably faster than 8 sequential `verify` calls on a typical
  developer laptop. (Soft target: ≥1.5× speedup; ML-DSA batching
  is conservative compared to BLS aggregation.)
- **SC-004**: One ML-DSA-65 sign completes in under 50 ms on a
  typical developer laptop; one verify in under 50 ms.
- **SC-005**: Signature wire-format size is exactly 3294 bytes
  (1-byte alg ID + 3293-byte ML-DSA sig). Public-key wire-format
  size is exactly 1953 bytes.
- **SC-006**: A reviewer can confirm the absence of an
  `aggregate` method on `PqSignature` in under 30 seconds by
  reading the contract doc.

## Assumptions

- Constitution v2.0.0 holds; quantum adversaries are in scope.
- Signatures are forward-secret with respect to the
  harvest-now-decrypt-later threat — only forgery (post-quantum) is
  the risk being mitigated. Migration timing is therefore "before
  Shor is real" rather than "before HNDL collection grows
  meaningful."
- ML-DSA-65 is the chosen parameter set. BSI TR-02102-1 recommends
  parameter set 3 (= ML-DSA-65) for general-purpose use; the
  parameter-set 5 (= ML-DSA-87) variant gives higher security
  margin at ~50% larger signatures. Defer ML-DSA-87 to a future
  high-assurance spec.
- Bouncy Castle's `org.bouncycastle.pqc.crypto.crystals.dilithium.*`
  classes provide ML-DSA-65 implementation (BC retains the legacy
  "Dilithium" name; algorithm is FIPS 204 ML-DSA).
- The classical `BLS` object stays in service (with deprecation
  warning) for the duration of the migration. Specs 004
  mixer-attestations and 006 config-chain make their own PQ-cutover
  decisions per-feature.
- No hybrid classical+PQ signature scheme. Per 011 research R6 and
  BSI / ENISA guidance, signature hybrid is rarely worth the cost;
  the cleanest migration is a PQ-only cutover per consumer.
