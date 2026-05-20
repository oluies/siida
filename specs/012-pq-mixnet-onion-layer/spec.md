# Feature Specification: PQ Mixnet Onion Layer (hybrid ML-KEM-768 + x25519)

**Feature Branch**: `012-pq-mixnet-onion-layer`

**Created**: 2026-05-20

**Status**: Draft

**Input**: Per 011-post-quantum-roadmap research.md row 1: replace
NaCl `box` (x25519 + XSalsa20 + Poly1305) on the round-aligned
onion layers with a hybrid handshake using ML-KEM-768 + x25519
combined under SHA3-256. The constitution v2.0.0 amendment
(quantum adversary with harvest-now-decrypt-later in scope) makes
this the first per-primitive PQ migration.

## Why this spec exists

The mixnet's onion encryption is the round-aligned wire traffic
that the global passive adversary sees. Today it uses NaCl `box`
which derives a shared secret via x25519 ECDH. x25519 is broken by
Shor's algorithm on a sufficiently large quantum computer; every
onion layer leaving the network today is a future-decrypted
ciphertext under the harvest-now-decrypt-later (HNDL) threat model
that constitution v2.0.0 Principle I makes explicit.

This is the **first** of the four per-primitive PQ migrations
(012-pq-mixnet-onion-layer, 013-pq-bls-replacement,
014-pq-config-chain-redesign, 015-pq-identity-encryption) reserved
by the 011 roadmap. It is intentionally first because the mixnet
onion layer is what the GPA sees — its HNDL exposure is the most
immediate concern.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A client encrypts an onion layer that survives quantum-capable retrospective decryption (Priority: P1)

A Siida client, sending a single round-aligned message through the
three-mixer chain (per the Vuvuzela architecture), produces a
ciphertext whose secrecy holds against a future quantum adversary
that captures the wire bytes today. The mixers strip layers
identically to the classical case; only the cryptographic
substrate changes.

**Why this priority**: The mixnet onion layer is the highest-volume
wire traffic Siida produces. HNDL exposure scales linearly with
unencrypted minutes. P1 because every other privacy guarantee
depends on this primitive holding.

**Independent Test**: A test fixture constructs a three-hop onion
using the new hybrid layer, transmits it through three simulated
mixers, and confirms the innermost payload decrypts to the original
plaintext. A separate "negative" test confirms that decapsulating
the layer with only the classical x25519 share (no ML-KEM share) —
simulating a quantum adversary who has solved the ECDLP but has no
prior access to ML-KEM secret keys — does NOT reveal the plaintext.

**Acceptance Scenarios**:

1. **Given** a recipient public bundle (`x25519_pk`, `ml_kem_pk`)
   and a single-layer onion targeting that recipient, **When** the
   recipient applies the receive procedure using both their
   `x25519_sk` and `ml_kem_sk`, **Then** the inner payload is
   recovered byte-for-byte.
2. **Given** a three-hop onion (client → A → B → C) constructed
   with three sets of mixer public bundles, **When** the onion is
   passed through mixers A, B, and C in order, **Then** mixer C
   recovers the innermost payload and mixers A and B see only
   correctly-stripped inner ciphertexts.
3. **Given** a captured onion-layer ciphertext, **When** an
   adversary supplies a correctly-derived x25519 shared secret but
   NO ML-KEM shared secret, **Then** the AEAD decryption fails
   (HNDL-resistance property).
4. **Given** the same hybrid receive procedure runs on Linux/amd64
   and macOS/arm64 with a fixed-seed RNG, **Then** the produced
   ciphertexts and the recovered plaintexts are bit-identical
   across architectures.

### User Story 2 - The wire format carries an algorithm-identifier byte so a hybrid → PQ-only cutover doesn't need a flag day (Priority: P1)

Every onion-layer ciphertext on the wire MUST carry a leading
1-byte algorithm identifier so a future spec can introduce a
PQ-only variant without breaking existing in-flight ciphertexts.
The classical-only NaCl `box` is treated as algorithm 0x00
(deprecated, not used by new specs); the hybrid this spec
introduces is algorithm 0x01; future PQ-only variants are 0x02+.

**Why this priority**: Without versioning, the eventual PQ-only
cutover (sketched as a far-future spec) becomes a global flag day,
which Siida cannot do safely while metadata-privacy guarantees
depend on continuous round operation. P1 because retrofitting
version bytes after a wire format has shipped is much harder than
shipping them now.

**Independent Test**: Every onion-layer byte produced by a 012-era
client starts with `0x01`; deserialisation rejects unknown
algorithm identifiers with a typed error; the existing classical
NaCl `box` code path (if still in service for any reason) is gated
behind a configuration flag that defaults OFF and emits a warning.

### User Story 3 - The KEM and ECDH paths are combined with a documented hash combiner (Priority: P1)

The hybrid handshake's shared secret MUST be derived by SHA3-256
over the concatenation of (classical x25519 shared secret) and
(ML-KEM-768 shared secret) with a domain-separation tag, per the
011 roadmap research R5. Naive concatenation is forbidden because
its security degrades to `min(classical, PQ)` against an adversary
that breaks one of the two.

**Why this priority**: A weak combiner undermines the entire point
of hybrid mode. P1 because this is the math, not the protocol
shape — getting it right once means future PQ-only cutover doesn't
need to revisit it.

**Independent Test**: A KAT vector pins the SHA3-256 output for a
known pair of (x25519_ss, ml_kem_ss) inputs and the documented
domain-separation tag. Any deviation from the documented combiner
construction breaks the KAT.

### Edge Cases

- **Recipient supplies only `x25519_pk` (no `ml_kem_pk` in their
  bundle)**: the layer-encrypt MUST refuse rather than fall back to
  classical-only mode. Documented in plan.md as a hard requirement;
  there is no graceful-degradation path that preserves HNDL
  resistance.
- **ML-KEM-768 ciphertext is much larger than the classical
  variant** (~1 KB vs ~32 bytes of classical key material). The
  mixnet's fixed-cell size assumption (from the privacy-preserving
  round protocol) MUST accommodate the new size; if it can't, this
  spec MUST flag the issue and either resize the cell (requiring
  coordination with 004-mixnet-server) or accept a metadata-overhead
  tradeoff.
- **Decapsulation failure on a mixer** (corrupted ciphertext): the
  mixer MUST NOT log the failure with any information identifying
  the sender, recipient, or round position. Standard
  no-side-channel-via-logs discipline (Constitution Principle I)
  applies.
- **Cross-architecture determinism** when a fixed-seed RNG is used
  for ML-KEM key generation: ML-KEM's deterministic key-derivation
  from a 32-byte seed (per FIPS 203) MUST produce byte-identical
  keys on every supported architecture. The implementation library
  chosen in plan.md must provide this deterministic mode for tests.
- **Algorithm-identifier rollback**: a mixer receiving a ciphertext
  whose algorithm identifier is older than its supported version
  (e.g., a 0x00 classical NaCl `box` arriving at a 0x01-only mixer)
  MUST refuse without revealing what algorithm IDs the mixer
  supports — refusal is uniform.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The onion layer's hybrid handshake MUST combine
  ML-KEM-768 (FIPS 203) and x25519 ECDH using SHA3-256 with the
  domain-separation tag `"siida/hybrid/v1/onion-layer"`. The
  combined shared secret is the 32-byte SHA3-256 output.
- **FR-002**: Each recipient publishes a "hybrid public bundle"
  containing `(x25519_pk: 32 bytes, ml_kem_pk: 1184 bytes)`.
  Distribution of this bundle is the responsibility of the PKG
  spec (005); 012 only defines the consumer side.
- **FR-003**: Each onion-layer ciphertext carries a 1-byte
  algorithm identifier as its FIRST byte. The value `0x01`
  identifies this spec's hybrid construction; `0x00` is reserved
  for classical NaCl `box` (deprecated); `0x02+` is reserved for
  future PQ-only variants.
- **FR-004**: AEAD over the combined shared secret MUST be
  ChaCha20-Poly1305 (RFC 8439). The nonce is a 12-byte counter
  derived from the layer position; the per-layer construction
  details live in `plan.md`.
- **FR-005**: A layer-encrypt operation MUST refuse if the
  recipient's hybrid public bundle is incomplete (missing
  `ml_kem_pk` or `x25519_pk`). Typed error
  `HybridOnionError.IncompleteBundle`. There is NO classical-only
  fallback.
- **FR-006**: A layer-decrypt operation MUST verify the algorithm
  identifier byte before any decapsulation. Unknown values return
  `HybridOnionError.UnsupportedAlgorithm`. The error is uniform —
  no side channel on which identifier was unsupported.
- **FR-007**: Both encapsulation (sender) and decapsulation
  (recipient) MUST be deterministic under fixed-seed RNG (for
  tests). Production paths use a cryptographically strong
  `SecureRandom`.
- **FR-008**: Test fixtures MUST include at least one
  three-hop onion-layer round-trip and at least one negative test
  proving HNDL-resistance (decryption fails given only the
  classical share).
- **FR-009**: Test KAT vectors MUST pin: the SHA3-256 combiner
  output for documented inputs; one full onion-layer encrypt-
  decrypt round under a fixed seed; the ML-KEM-768 key derivation
  output under a fixed seed (for cross-arch determinism check).
- **FR-010**: The public Scala API MUST live under
  `siida.crypto.api.HybridOnion` and follow the FR-010 stability
  pattern from spec 002 — once 012 lands, no rename or signature
  change without a follow-up spec.
- **FR-011**: The implementation MUST use an existing audited
  ML-KEM-768 library; no Siida-original lattice implementation.
  Plan.md picks between Bouncy Castle's PQ provider, liboqs via
  JNI, and any other candidates.
- **FR-012**: Files ported from upstream cryptographic libraries
  (if any) MUST retain their original licence headers per
  constitution Principle III, and be tracked in
  `build/licence-headers/ported.json`.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of KAT vectors (FR-009) pass on every CI run on
  both supported architectures (linux-amd64 and darwin-arm64).
- **SC-002**: Three-hop onion round-trip in `HybridOnionSuite`
  passes on every CI run.
- **SC-003**: The HNDL-resistance test (negative: classical-only
  decapsulation fails) passes — i.e., it confirms decryption is
  NOT possible without the ML-KEM secret.
- **SC-004**: One full hybrid onion-layer encrypt completes in
  under 50 ms on a typical developer laptop; one decapsulation in
  under 50 ms. (Loose sanity bounds; real round budgets are set
  by spec 004-mixnet-server.)
- **SC-005**: The layer's wire-format size is documented in
  `plan.md` and `contracts/wire-format.md`. If it exceeds the
  classical NaCl `box` size by more than 1.5 KB per layer, the
  spec MUST flag a coordination requirement with spec
  004-mixnet-server.
- **SC-006**: The licence-header check (constitution Principle III,
  001 FR-010) passes for every file in `modules/crypto/`
  introduced by this spec.

## Assumptions

- Constitution v2.0.0 holds: quantum adversaries (including HNDL)
  are in scope; the existing classical NaCl `box` remains in
  service only until this spec's hybrid layer is wired up by
  whichever spec consumes it (likely 004-mixnet-server or the
  client SDK in 007).
- The mixnet round protocol's fixed-cell size assumption can
  accommodate the ML-KEM-768 ciphertext overhead (~1 KB per layer).
  If 004-mixnet-server's spec hasn't been written yet when 012
  lands, this assumption is documented as a constraint on 004.
- ML-KEM-768 (FIPS 203) is the chosen parameter set. ML-KEM-1024
  is overkill for "128-bit classical equivalent" PQ security; the
  768 variant maps to BSI TR-02102-1's recommended security
  level for general-purpose use.
- x25519 stays in the hybrid as the classical half (rather than
  Curve448) because the existing Siida stack already uses x25519
  (NaCl `box`) and the move-the-line cost of a hybrid is the
  smaller delta. A future spec may bump the classical half if BSI
  recommends Curve448 for higher-assurance deployments.
- ChaCha20-Poly1305 (RFC 8439) is the chosen AEAD. The NaCl `box`
  currently uses XSalsa20+Poly1305; switching to ChaCha20 aligns
  with broader cryptographic standardisation and IETF
  recommendations and gives us better-vetted nonce-misuse
  resistance.
- The ML-KEM library choice is deferred to plan.md but constrained
  by Principle III (Apache-2.0 / MIT / BSD acceptable; LGPL
  acceptable for the Apache-licence-equivalent classpath
  exception; AGPL-incompatible licences forbidden).
- No external KAT for the full Siida hybrid handshake exists; we
  derive KATs from a fixed-seed harness against a chosen reference
  implementation (gnark-crypto BN254 was self-referential the same
  way in 002). This is a known limitation; external validation is
  a follow-up.
- The PKG (spec 005) will issue hybrid public bundles. Until 005
  ships, the test fixtures in 012 construct bundles inline.
