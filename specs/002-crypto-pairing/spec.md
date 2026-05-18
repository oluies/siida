# Feature Specification: Crypto Pairing (BN254 + IBE + BLS)

**Feature Branch**: `002-crypto-pairing`

**Created**: 2026-05-17

**Status**: Draft

**Input**: User description: "Replace Alpenhorn's dclxvi/bn256 pairing implementation with a portable BN254 path on the JVM, and port the ibe (Identity-Based Encryption) and bls (BLS signature) packages from github.com/vuvuzela/crypto onto that new primitive. Decide between (a) gnark-crypto reached over JNI and (b) a pure-Scala BN254 implementation as part of this spec — both candidates evaluated against build portability across Linux/amd64 and macOS/arm64, audit surface for AGPL provenance, and round-deterministic test viability. Preserve BSD-3-clause headers on ported files per constitution Principle III; new code is AGPL-3.0-or-later."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - IBE round-trip works on the new pairing primitive (Priority: P1)

A downstream module — initially the PKG (004) and the client SDK (006),
ultimately every component that talks to the PKG-bootstrapped key system
— needs to encrypt a message to an identity string (e.g., a username or
a config-chain epoch ID) and have the recipient decrypt it using a key
issued from a known master public key. The crypto module provides
exactly that primitive, built on BN254 instead of the legacy BN256, and
its correctness is mechanically demonstrable on every supported
architecture.

**Why this priority**: IBE is the single most load-bearing primitive in
the Alpenhorn/Vuvuzela design. Until it works correctly on BN254,
neither the PKG (004) nor the client SDK (006) nor the config-chain
governance (005) can be built; every downstream spec from 003 onward
depends on this primitive being present and correct.

**Independent Test**: A test fixture (a) sets up a master key pair,
(b) issues a per-identity decryption key, (c) encrypts a known message
to that identity, (d) decrypts and recovers the original byte-for-byte,
and (e) shows that decryption with a key for a *different* identity
fails. Run the same fixture on Linux/amd64 and on macOS/arm64; outputs
match.

**Acceptance Scenarios**:

1. **Given** a freshly generated master key pair and a per-identity
   decryption key issued from it, **When** a contributor calls IBE
   encrypt for that identity and IBE decrypt with that key, **Then**
   the recovered plaintext equals the original message byte-for-byte.
2. **Given** an IBE ciphertext encrypted to identity `A`, **When** a
   contributor attempts to decrypt with a key issued for identity `B`,
   **Then** decryption fails with a typed error and reveals no
   plaintext bits.
3. **Given** the IBE round-trip executed with a fixed RNG seed,
   **When** the same test is executed on Linux/amd64 and on macOS/arm64,
   **Then** the produced ciphertext and recovered plaintext are
   bit-identical across architectures.
4. **Given** a known-answer test vector (master key, identity, message,
   expected ciphertext), **When** the IBE encrypt operation runs,
   **Then** the produced ciphertext matches the test vector exactly.

---

### User Story 2 - BLS sign / verify / aggregate works on the new pairing primitive (Priority: P2)

Components that need authenticated, public-verifiable signatures — the
config-chain (005), mixer attestations (003), and any future
agent-identity proofs (007) — need BLS sign, verify, and signature
aggregation. The crypto module provides these on BN254 with the same
portability guarantees as IBE.

**Why this priority**: BLS unblocks the config-chain governance layer
(005). Without it, the PKG (004) can issue keys but the set of trusted
PKGs and mixers can't be rotated under an auditable trust chain. P2
because IBE (US1) is strictly more load-bearing — a system with IBE
and no BLS can still bootstrap a single trusted PKG; the inverse is
not true.

**Independent Test**: A test fixture (a) generates a BLS keypair,
(b) signs a known message, (c) verifies the signature, (d) aggregates
two independent signatures over the same message into a single
aggregate signature, and (e) verifies the aggregate. The same fixture
runs deterministically across Linux/amd64 and macOS/arm64.

**Acceptance Scenarios**:

1. **Given** a BLS keypair, **When** a contributor signs a known
   message and verifies with the matching public key, **Then**
   verification succeeds.
2. **Given** the same signature, **When** verification is attempted
   with a *different* public key, **Then** verification fails and
   returns a typed error.
3. **Given** two BLS signatures over the same message from two
   independent signers, **When** they are aggregated and the aggregate
   is verified against the two public keys, **Then** verification
   succeeds.
4. **Given** the same sign/verify/aggregate sequence with fixed RNG
   seeds, **When** run on Linux/amd64 and on macOS/arm64, **Then**
   the produced signatures, the aggregate, and the verification
   outcomes are bit-identical.

---

### User Story 3 - BN254 primitives are an internal API future modules can build on (Priority: P3)

A future feature (005 config-chain proofs, 007 agent identity, possibly
009 observability for cryptographic-event metrics) needs lower-level
access to the pairing primitive — scalar arithmetic, G1/G2 point
addition and scalar multiplication, pairing evaluation, hash-to-curve
— without re-implementing it. The crypto module exposes a stable,
documented internal Scala API for these operations.

**Why this priority**: P3 because IBE and BLS (US1, US2) are the only
named consumers in this spec; lower-level access is an enabler for
later specs, not a current blocker. Still in 002's scope because
exposing a clean API now avoids retrofitting once IBE and BLS have
locked in the layering.

**Independent Test**: For each of {G1 scalar-mul, G2 scalar-mul,
G1+G1 add, G2+G2 add, e(G1, G2) pairing, hash-to-G2}, a contributor
can call the operation from a new module without touching the
crypto module's internals, and a known-answer test vector verifies
the result.

**Acceptance Scenarios**:

1. **Given** a known scalar `s` and a known G1 point `P`, **When** a
   contributor calls G1 scalar-mul, **Then** the result equals the
   test-vector point.
2. **Given** known G1 and G2 generators, **When** a contributor calls
   the pairing `e(g1, g2)`, **Then** the result equals the documented
   GT element.
3. **Given** a known identity byte string, **When** a contributor
   calls hash-to-G2, **Then** the produced G2 point equals the
   test-vector point.

---

### Edge Cases

- **Mixed-curve input**: a caller passes a BN256-encoded point or
  scalar into a BN254 operation; the call must fail with a typed
  error rather than silently producing garbage.
- **Identity-element corner cases**: pairing of the identity element,
  scalar multiplication by zero, sign with the zero scalar — each
  must return a well-defined result documented in the API contract
  (typically a typed error or the identity element, never undefined
  behaviour).
- **Malformed serialised input**: a ciphertext, signature, or point
  whose byte representation is the wrong length or fails subgroup
  membership must be rejected before any expensive operation runs;
  rejection must not leak timing information about the structure of
  the malformed input.
- **Cross-architecture determinism**: encrypt on Linux/amd64, decrypt
  on macOS/arm64 (and vice versa); plaintexts must match
  byte-for-byte. This is the load-bearing portability claim of the
  whole spec.
- **Random-number-source variance**: tests use a fixed-seed RNG; a
  contributor accidentally seeding from system entropy must be caught
  by a CI gate (the test framework MUST refuse non-deterministic
  randomness in this module's test suite).
- **Performance regression**: an order-of-magnitude slowdown in
  pairing evaluation between two PRs must be flagged; not part of
  this spec's MUSTs but the test fixtures SHOULD record per-op timing
  for downstream observability work.
- **Architecture mismatch in native binaries** (only relevant if the
  plan chooses JNI to gnark-crypto): a developer on macOS/arm64 must
  not need to hand-install an x86 native library; the build either
  ships per-arch artefacts or falls back to a portable implementation.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The crypto module MUST provide IBE encrypt and decrypt
  operations over BN254 with the same cryptographic semantics as
  the Vuvuzela `crypto/ibe` package (Boneh-Franklin IBE, type-3
  pairing).
- **FR-002**: The crypto module MUST provide BLS sign, verify, and
  signature aggregation over BN254 with the same cryptographic
  semantics as the Vuvuzela `crypto/bls` package.
- **FR-003**: The underlying pairing primitive MUST be BN254 (not
  BN256). Any reference to a BN256 curve in the public Scala API of
  the crypto module MUST be removed; if a transitional shim is
  required for porting, it MUST live in test fixtures only and be
  documented as such.
- **FR-004**: All operations (FR-001, FR-002, plus the lower-level
  BN254 primitives in US3) MUST produce bit-identical outputs on
  Linux/amd64 and macOS/arm64 for fixed-RNG-seed test fixtures.
- **FR-005**: The crypto module's public Scala API MUST surface IBE
  and BLS operations with typed error returns (no exceptions for
  expected failure modes such as invalid ciphertext, malformed point,
  wrong-identity decryption); exceptions are reserved for programming
  errors and resource failures.
- **FR-006**: Test fixtures MUST be deterministic — fixed RNG seed,
  no system clock, no network I/O. The test suite MUST fail loudly if
  a contributor introduces non-deterministic randomness.
- **FR-007**: Known-answer test vectors MUST be present for: IBE
  encrypt (one vector minimum), BLS sign and BLS aggregate (one
  vector each minimum), and the underlying G1 scalar-mul, G2
  scalar-mul, pairing evaluation, and hash-to-G2 operations (one
  vector each minimum). Vectors MUST come from a documented external
  source (e.g., upstream gnark-crypto tests, IETF draft vectors) so
  the audit trail does not depend on Siida's own implementation
  being correct.
- **FR-008**: Files ported from `github.com/vuvuzela/crypto` MUST
  retain their original BSD-3-clause headers at file scope; their
  paths MUST be added to `build/licence-headers/ported.json` so the
  existing licence-header gate (constitution Principle III, feature
  001 FR-010) treats them correctly. Files newly authored for this
  module MUST carry the AGPL-3.0-or-later header.
- **FR-009**: The choice between gnark-crypto-over-JNI and a
  pure-Scala BN254 implementation MUST be made and recorded in this
  feature's `plan.md` and `research.md`; the chosen path MUST satisfy
  FR-004 (cross-arch determinism) and the constitution's licence
  policy (Principle III). The rejected alternative MUST be documented
  with the reasons for rejection, so a future feature can revisit
  the decision without re-deriving the trade-offs.
- **FR-010**: The crypto module's public API MUST be stable enough
  for downstream specs (003 mixnet, 004 PKG, 005 config-chain, 006
  SDK) to depend on it without expecting renames or signature changes
  during their own implementation; any post-002 API change is a
  spec-level event requiring its own `plan.md` Complexity Tracking
  entry.
- **FR-011**: The crypto module's test suite MUST run as part of the
  standard `make test` (or whatever the constitution-pinned bootstrap
  test target is at the time 002 lands); no separate manual step.
- **FR-012**: The crypto module MUST NOT introduce any persistent
  state, network I/O, logging of user identifiers, or telemetry; it
  is a pure-computation module by intent (constitution Principle I:
  no side channels through telemetry).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of the IBE, BLS, and BN254-primitive known-answer
  test vectors (FR-007) pass on every CI run, on both supported
  architectures.
- **SC-002**: Cross-architecture determinism: for every test fixture
  with a fixed seed, the bit-level output on Linux/amd64 equals the
  bit-level output on macOS/arm64. Measured by serialising the test
  outputs and comparing byte streams.
- **SC-003**: A new contributor adding a downstream module that
  consumes the crypto API can do so without modifying the crypto
  module itself — measured by the absence of cross-module commits
  in 003-008 that touch `modules/crypto/`.
- **SC-004**: A pairing operation on BN254 completes in under 50ms
  on a typical developer laptop; an IBE encrypt completes in under
  100ms; a BLS sign completes in under 50ms. (These are sanity
  upper bounds; tighter per-operation performance targets belong
  in a later observability spec.)
- **SC-005**: The licence-header check (constitution Principle III,
  feature 001 FR-010) passes for every file in `modules/crypto/`,
  including newly authored AGPL files and ported BSD-3-clause
  files via the allowlist mechanism.
- **SC-006**: An auditor inspecting the crypto module can answer
  "where did this code come from?" for every file by checking the
  combination of `NOTICE`, `build/licence-headers/ported.json`, and
  the file's own header — no investigation outside the repository
  is required.

## Assumptions

- The constitution's stack lock (Scala 3 + Pekko + Cats Effect 3 +
  Mill, JDK 21 LTS) holds; the crypto module obeys it.
- Siida is pre-alpha. Wire compatibility with deployed Vuvuzela
  instances using BN256 is **out of scope**; this is a clean break.
  Test vectors and external reference data may come from BN254
  ecosystem sources (gnark-crypto, IETF BLS drafts, py_ecc) rather
  than the original Vuvuzela network.
- The IBE construction is Boneh-Franklin over a type-3 pairing on
  BN254. If a future security review prefers a different IBE scheme,
  that is a separate spec; 002 ports the existing Vuvuzela IBE
  semantics to the new curve.
- The BLS construction follows the same convention used by Vuvuzela's
  `crypto/bls` (rogue-key-resistance via proofs-of-possession or
  message-hashing — whichever the upstream uses; the plan resolves
  which when reading the upstream code).
- The hash-to-curve construction follows a documented, audited
  standard (e.g., IETF draft-irtf-cfrg-hash-to-curve, BLS12-381's
  established maps adapted to BN254). The plan picks the exact
  variant and records it in `research.md`.
- The chosen implementation (gnark-crypto JNI vs pure-Scala) does
  not require any contributor to install a global toolchain beyond
  the JDK 21 LTS pinned by 001; if JNI is chosen, all native
  binaries either ship pre-built per-arch or are built hermetically
  during the Mill build.
- The Vuvuzela `crypto` repository is BSD-3-clause at file scope;
  this assumption is verified by the plan when reading source files
  to be ported. If a file turns out to be AGPL-licensed, it follows
  the AGPL path instead and `ported.json` is not used for it.
- Performance bounds in SC-004 are sanity upper bounds, not the
  ultimate targets. Real round-budget timing is set by the mixnet
  spec (003); the crypto spec just ensures the primitives aren't
  catastrophically slow.
