# Feature Specification: PQ Identity Encryption (PKG-Directory + HybridOnion)

**Feature Branch**: `015-pq-identity-encryption`

**Created**: 2026-05-20

**Status**: Draft — design spec; spec 005 (PKG) consumes

**Input**: Per 011-post-quantum-roadmap research.md row 4: replace
Boneh-Franklin IBE with a PKG-directory model + ML-KEM-768. **This
is a protocol-level redesign, not a primitive swap** — Boneh-Franklin
IBE provides a property (encrypt-to-identity without prior key
lookup) that no production-grade PQ-IBE preserves.

## Why this spec exists

Spec 002 shipped Boneh-Franklin IBE over BN254. Constitution v2.0.0
flags BN254 pairings as quantum-vulnerable. The replacement needs
to provide a working encryption primitive for the
identity-addressed flow (a sender knows the recipient's identity
string and wants to encrypt a message without first round-tripping
to the recipient).

No production-grade PQ-IBE scheme exists. Lattice-based IBE
constructions (Agrawal-Boneh-Boyen, GGH-derived) are research-stage
as of 2026. Code-based and isogeny-based candidates are similarly
not standardised. Per 011 R1's per-primitive analysis, the
pragmatic alternative is a **PKG-directory architecture**:

- Each user/identity has a stable public bundle (`HybridOnion`
  bundle from spec 012)
- The PKG (spec 005) maintains a directory mapping
  `identity_string → HybridPublicBundle`
- Senders query the PKG-directory before encrypting
- Encryption itself uses `HybridOnion.encrypt` (already PQ from 012)

**Privacy cost**: the PKG learns "X queried for Y's bundle." The
original Boneh-Franklin IBE did NOT reveal this — only the master
public key was needed to encrypt to any identity. This spec
documents the trade-off explicitly and offers mitigations.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Sender encrypts to a recipient identity via the PKG-directory + HybridOnion (Priority: P1)

A sender knows a recipient's identity string (e.g., `"alice@siida"`)
and wants to encrypt a message such that only the holder of that
identity's secret bundle can decrypt. Today the sender:

1. Queries the PKG-directory for the bundle matching the identity
2. Receives a signed `HybridPublicBundle` from the PKG (signature
   verified against the PKG's published `MultiSignedEntry` chain
   from 014)
3. Calls `HybridOnion.encrypt` to produce the ciphertext

The recipient decapsulates with their `HybridSecretBundle` (held
since the PKG issued it; this part is spec 005's concern).

**Why this priority**: P1 because this is the load-bearing
end-to-end encryption flow Siida uses for human chat and agent
messaging. Without it, the messaging substrate has no PQ-safe
encryption path.

**Independent Test**: A test fixture mounts an in-memory
PKG-directory with 3 identity → bundle entries; a sender resolves
one identity, encrypts a message, the recipient decrypts and
recovers it byte-for-byte.

**Acceptance Scenarios**:

1. **Given** an in-memory directory mapping `"alice@siida" → bundle_alice`,
   `"bob@siida" → bundle_bob`, **When** the sender calls
   `IdentityEncryption.encrypt(directory, "alice@siida", message, rng)`,
   **Then** the result is an `IdentityCiphertext` that
   `IdentityEncryption.decrypt(secret_alice, ct)` recovers to the
   original message.
2. **Given** the same setup, **When** the sender targets a
   non-existent identity `"unknown@siida"`,
   **Then** `encrypt` returns `Left(IdentityNotFound)`.
3. **Given** the same setup, **When** an attacker holding only
   `secret_bob` tries to decrypt a ciphertext targeting alice,
   **Then** decryption fails with `DecapsulationFailed`
   (HNDL-resistant per 012's hybrid construction).

### User Story 2 - PKG-directory entries are signed and verifiable (Priority: P1)

Every directory entry the sender receives is signed by the PKG
roster (using `MultiSignedEntry` from 014). Senders verify the
signature chain before trusting the bundle — otherwise an
intermediate party could substitute a bundle they control and
intercept future ciphertexts.

**Why this priority**: P1 because directory integrity is the
security hinge of the whole design. An unsigned directory means
any active adversary on the lookup path can man-in-the-middle.

**Independent Test**: A signed-directory fixture is constructed
with valid PKG-roster signatures; the sender's verifier accepts.
A tampered directory entry (re-signed under an unrelated key)
is rejected.

**Acceptance Scenarios**:

1. **Given** a directory with PKG-roster-signed entries,
   **When** the sender calls `lookup(directory, identity)`,
   **Then** the verifier checks the entry's `MultiSignedEntry`
   against the PKG roster and returns the bundle on success.
2. **Given** the same directory but with a tampered signature
   on one entry, **When** the sender calls `lookup`,
   **Then** the verifier returns `Left(InvalidDirectorySignature)`.

### User Story 3 - Privacy trade-off: directory queries are anonymously routed (Priority: P2)

The PKG-directory architecture inherently reveals "X asked for Y's
bundle" to the PKG. This is a regression versus Boneh-Franklin
IBE, which let senders encrypt without any per-message PKG
interaction. **015 documents the trade-off and mandates that the
operational deployment route directory queries anonymously** —
typically through the mixnet itself, treating the PKG as just
another recipient on the network.

**Why this priority**: P2 because the functional encryption flow
works without anonymous routing (US1/US2 are independent). But
the constitution v2.0.0 Principle I privacy guarantee is materially
weaker without it; this spec mandates the mitigation so spec 005
(PKG) and spec 007 (SDK) build in the right shape.

**Independent Test**: The 015 spec's "deployment guidance" section
documents the recommended anonymous-lookup pattern. Spec 005's PKG
implementation includes a `lookupViaMixnet` method that 007's SDK
calls; the privacy-property regression is contained.

### Edge Cases

- **Directory miss / stale entry**: a sender's cached directory
  may not contain a freshly-issued identity. The lookup returns
  `IdentityNotFound`; the sender retries against a fresh directory
  snapshot or queries the PKG live. Caching strategy is the SDK's
  (007) concern.
- **Directory entry expired (roster rotation)**: directory entries
  carry the PKG roster's epoch number. If the roster epoch has
  moved past the entry's signing epoch, the verifier MAY accept
  with a warning (entry is "stale-but-valid") or reject as
  `StaleDirectoryEntry`. 015 RECOMMENDS reject; 005 decides.
- **PKG-directory size**: a directory listing all identities can
  be very large (millions of bundles × 1216 bytes each ≈ low GB).
  The SDK should fetch incrementally or via a Bloom filter for
  cache-miss detection. Out of 015's scope; 005/007 own this.
- **HNDL resistance preserved**: even though the directory lookup
  is observable, the ciphertext itself uses `HybridOnion.encrypt`
  whose HNDL-resistance is established in 012. An adversary
  storing today's ciphertexts and tomorrow's quantum computer
  still can't recover the plaintext.
- **Identity-string collision**: two different humans pick
  `"alice@siida"`. Resolution is the PKG's policy (first-come,
  display-name disambiguation, etc.) — out of 015's scope.
- **Directory poisoning**: an adversary submits many fake
  identity → bundle pairings to the PKG. The PKG's onboarding
  policy (proof-of-ownership of an identity, rate limits) defends.
  Out of 015's scope.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The crypto module MUST expose
  `siida.crypto.api.IdentityEncryption` with `encrypt(directory:
  Directory, identity: Array[Byte], message: Array[Byte], rng:
  SecureRandom): Either[IdentityEncError, IdentityCiphertext]` and
  `decrypt(secret: HybridOnion.HybridSecretBundle, ct:
  IdentityCiphertext): Either[IdentityEncError, Array[Byte]]`.
- **FR-002**: `IdentityCiphertext` is a thin wrapper around a
  `HybridOnion.OnionLayer` plus a 1-byte algorithm-ID prefix
  (`0x20` for this spec). The crypto bulk comes from 012's
  HybridOnion.
- **FR-003**: A `Directory` is an in-memory map from
  identity-bytes to `HybridPublicBundle` plus a `MultiSignedEntry`
  proof per entry. The directory data structure is opaque; spec
  005 (PKG) defines the persistent / network representation.
- **FR-004**: `encrypt` MUST refuse if the identity is not in the
  directory: `Left(IdentityNotFound)`. There is NO fallback
  encryption path that bypasses directory lookup.
- **FR-005**: `encrypt` MUST verify the directory entry's
  `MultiSignedEntry` signature against the PKG roster passed
  alongside the directory. Failure → `Left(InvalidDirectorySignature)`.
- **FR-006**: `decrypt` MUST be HNDL-resistant by construction
  (transitively, via `HybridOnion.decrypt`).
- **FR-007**: The deployment guidance section of this spec MUST
  describe the anonymous-lookup pattern: directory queries SHOULD
  be routed through the mixnet itself, with the PKG appearing as
  a recipient on the network. SDK (007) is responsible for the
  actual routing.
- **FR-008**: Wire format MUST be self-versioning: `0x20`
  algorithm ID for this spec's identity-encryption variant; future
  variants get `0x21+`.
- **FR-009**: Test fixtures MUST be deterministic.
- **FR-010**: API surface stability (same FR-010 pattern as
  002/012/013/014).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: End-to-end encrypt-via-directory + decrypt
  round-trip recovers the original message byte-for-byte; tested
  on darwin-arm64 and linux-amd64.
- **SC-002**: `IdentityNotFound` on a directory miss is correctly
  returned (deterministic test).
- **SC-003**: HNDL-resistance for `IdentityEncryption` ciphertexts
  is inherited from 012's `HybridOnion` and demonstrated by the
  same kind of negative test (classical-only decapsulation fails).
- **SC-004**: A tampered directory entry signature is rejected with
  `InvalidDirectorySignature`.
- **SC-005**: Documentation (in `contracts/threat-model.md` of this
  spec) explicitly compares the privacy properties of
  Boneh-Franklin IBE vs PKG-directory + HybridOnion, and states the
  anonymous-lookup mitigation requirement.
- **SC-006**: One full encrypt-decrypt round-trip completes in
  under 100 ms on a typical developer laptop.

## Assumptions

- Constitution v2.0.0 holds.
- Spec 012 ships first (provides `HybridOnion`).
- Spec 013 ships first (provides `PqSignature`, used transitively
  via 014's `MultiSignedEntry`).
- Spec 014 ships first (provides `MultiSignedEntry` for directory
  entry attestation).
- The PKG (spec 005) is responsible for:
  - Maintaining the master directory
  - Issuing initial `HybridSecretBundle`s to identities (via
    out-of-band onboarding, signed by the PKG roster)
  - Signing directory entries with `MultiSignedEntry`
  - Rotating its own roster via the config chain (006)
- The SDK (spec 007) is responsible for:
  - Caching directory entries
  - Routing directory lookups through the mixnet anonymously
  - Re-fetching on roster rotation
- The privacy degradation from "PKG sees lookups" is acknowledged
  and documented; the mitigation is anonymous routing of
  directory queries. The mitigation is partial — a global passive
  adversary watching the mixnet's egress to the PKG sees query
  traffic volume even if it can't link queries to senders.
- No effort is made to implement a lattice-based PQ-IBE scheme.
  When and if one is standardised (years out), a future spec may
  revisit this design.
