# Feature Specification: PKG Key-Bootstrap (Identity Issuance + Directory)

**Feature Branch**: `005-pkg-keybootstrap`

**Created**: 2026-05-20

**Status**: Draft — MVP. Friend-discovery (Alpenhorn-style),
persistent storage, network transport, and roster rotation are
explicit non-goals.

**Input**: Per the roadmap entry: "Alpenhorn-style private key
generator and friend-discovery primitives." Spec 015 already
shipped the `Directory` trait and `MultiSignedEntry` consumer
side. Spec 004 shipped the mailbox-id space. This spec
implements the **Private Key Generator (PKG)** — the
identity-issuance service that backs 015's directory.

## Why this spec exists

Spec 015 redesigned identity-addressed encryption around a
PKG-maintained directory. The directory is a map of
`identity → HybridPublicBundle` plus a `MultiSignedEntry` proof
attesting that the PKG roster signed off on the binding. Spec
015 ships the **consumer** (sender + recipient sides); spec 005
ships the **producer** — the PKG that issues identities, holds
the roster keys, and constructs the signed directory entries.

The MVP is in-memory, single-PKG-roster, with no friend-discovery
sub-protocol and no persistent state. Production deployment of
the PKG (persistent storage, network APIs, sybil-resistance
policies, roster rotation via the config chain) is the work of
follow-up specs.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Issue an identity, receive a HybridSecretBundle, and find it in the directory (Priority: P1)

A new user registers with the PKG using an identity string
(e.g., `"alice@siida"`). The PKG:

1. Generates a fresh `HybridSecretBundle` via
   `HybridOnion.generateBundle(rng)`
2. Allocates a mailbox-id (next sequential, skipping the
   reserved values from spec 004)
3. Signs the binding
   `(identity, public_bundle, mailbox_id)` with the PKG roster's
   ML-DSA-65 keys (threshold M of N) — produces a
   `MultiSignedEntry`
4. Adds the entry to the directory
5. Returns the `HybridSecretBundle` (and the mailbox-id) to the
   user out-of-band

Later, when a sender queries the directory for
`"alice@siida"`, the verification succeeds and the bundle is
returned.

**Why this priority**: P1 because identity issuance is the
load-bearing PKG function. Without it, the directory has no
entries and 015's encryption flow has nothing to look up.

**Independent Test**: A PKG fixture with a 3-of-5 roster issues
alice + bob + carol. A sender queries the resulting directory
for each identity; all three lookups succeed.

**Acceptance Scenarios**:

1. **Given** an empty PKG with a 3-of-5 ML-DSA-65 roster,
   **When** the PKG calls `issueIdentity("alice@siida", rng)`,
   **Then** it returns a `HybridSecretBundle` and a non-reserved
   mailbox-id, and the directory now contains a signed entry
   for `"alice@siida"`.
2. **Given** the PKG state above, **When** a sender calls
   `directory.lookup("alice@siida".getBytes)`,
   **Then** the returned `Right(bundle)` matches the public-key
   half of the bundle returned by `issueIdentity`.
3. **Given** the PKG issuance happened with a fixed-seed RNG,
   **When** the test re-runs with the same seed,
   **Then** the issued bundle, mailbox-id, and directory entry
   are byte-identical (cross-architecture deterministic).

### User Story 2 — Duplicate identity issuance is rejected (Priority: P1)

If the same identity string is offered to `issueIdentity` twice,
the PKG MUST reject the second call. Identity collision is a
policy concern (out-of-scope for the crypto layer), but the PKG
crypto layer enforces uniqueness as a safety property — silently
accepting duplicates would let an attacker who knows a victim's
identity string replace the binding.

**Why this priority**: P1 because identity uniqueness is a basic
integrity property. Other policy (proof-of-ownership, rate
limiting, display-name disambiguation) is layered on top by
follow-up specs.

**Independent Test**: Issue alice twice; the second call returns
`Left(PkgError.IdentityAlreadyExists)` without mutating PKG
state.

**Acceptance Scenarios**:

1. **Given** a PKG that has issued `"alice@siida"`,
   **When** `issueIdentity("alice@siida", rng)` is called again,
   **Then** the result is `Left(IdentityAlreadyExists)` and the
   directory still contains exactly one alice entry.

### User Story 3 — Directory snapshot returns a verifiable `Directory` (Priority: P1)

The PKG exposes its directory as an `IdentityEncryption.Directory`
instance — the same opaque type spec 015 consumes. The snapshot
includes all currently-issued identities with their
`MultiSignedEntry` proofs.

**Why this priority**: P1 because this is the integration point
between PKG (producer) and 015's IdentityEncryption (consumer).
Without a working snapshot, senders can't address recipients.

**Independent Test**: After issuing 3 identities, the PKG's
`directorySnapshot()` returns a `Directory` whose `lookup` calls
succeed for all 3.

**Acceptance Scenarios**:

1. **Given** a PKG with alice, bob, carol issued,
   **When** the SDK gets a snapshot via
   `pkg.directorySnapshot()`,
   **Then** the resulting `Directory` resolves each identity
   string back to the matching public bundle, with the signature
   verification passing.

### Edge Cases

- **Reserved mailbox-id space**: The PKG MUST skip
  `MixChain.CoverMailboxId` (0) and `MixChain.BroadcastMailboxId`
  (-1) when allocating. The MVP allocates sequentially starting
  at 1; the test verifies that 0 and -1 are never returned.
- **Empty roster**: A PKG configured with zero roster keys is a
  configuration error — `Pkg.create(...)` rejects it with
  `Left(PkgError.EmptyRoster)`.
- **Threshold > roster size**: Threshold > N is a configuration
  error — same handling.
- **Identity with binary bytes (not UTF-8)**: identities are
  `Array[Byte]` not `String` — the PKG doesn't impose encoding.
  Two byte-identical identity arrays collide; otherwise they're
  distinct.
- **Mailbox-id space exhaustion**: 2^63 mailboxes is effectively
  infinite for any deployment; out-of-scope for the MVP.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The PKG module MUST expose `siida.pkg.api.Pkg`
  with:
  - `Pkg.create(rosterPublicKeys, rosterPrivateKeys, threshold,
    domainSeparationTag, mailboxIdSeed)` — constructor that
    validates the configuration
  - `pkg.issueIdentity(identity: Array[Byte], rng: SecureRandom)`
    — returns `Either[PkgError, IssuedIdentity]`
  - `pkg.directorySnapshot()` — returns
    `IdentityEncryption.Directory`
- **FR-002**: An `IssuedIdentity` MUST contain:
  - The full `HybridSecretBundle` (delivered to the user
    out-of-band)
  - The allocated mailbox-id
  - The corresponding public-bundle bytes and the
    `MultiSignedEntry` proof (echoed back for verification)
- **FR-003**: The PKG MUST refuse to issue a duplicate identity
  with `Left(IdentityAlreadyExists)`.
- **FR-004**: The PKG MUST allocate mailbox-ids in the range
  `[1, Long.MaxValue]`, skipping `MixChain.CoverMailboxId` (0)
  and `MixChain.BroadcastMailboxId` (-1).
- **FR-005**: The PKG roster MUST sign the directory entry using
  exactly `threshold` of its `N` roster signing keys. The MVP
  signs with signers `[0, threshold)` (the first M signers); a
  follow-up spec adds policy-driven signer selection.
- **FR-006**: The PKG signs over the wire-format byte sequence
  `identity_length (uint16 BE) || identity_bytes ||
  mailbox_id (uint64 BE) || public_bundle_wire_bytes` as the
  `MultiSignedEntry` payload. The directory consumer
  (`Directory.inMemory`) reads back `public_bundle_wire_bytes`
  from this payload to recover the bundle.
- **FR-007**: `directorySnapshot()` MUST be a pure-function read
  — same PKG state produces the same `Directory` byte-for-byte.
- **FR-008**: API stability (FR-010 pattern from prior specs):
  the public Scala API of `siida.pkg.api.*` is locked once 005
  merges.
- **FR-009**: Test fixtures MUST be deterministic.

### Out-of-scope (deferred to follow-up specs)

The MVP does NOT include:

- **Friend-discovery sub-protocol** (Alpenhorn-style): the
  "add request" / "add response" message exchange that lets one
  identity discover another's public bundle via the PKG. This
  is a non-trivial protocol on its own; a separate spec.
- **Persistent storage** for the PKG state. MVP is in-memory;
  restarting the PKG loses all issued identities.
- **Network transport** for issuance requests or directory
  fetches. The PKG API is in-process only.
- **Sybil resistance / proof-of-ownership**: the policy layer
  that decides who can register what identity. Spec 005's PKG
  accepts any `issueIdentity` call (subject to FR-003).
- **Rate limiting**: per-identity, per-IP, per-roster limits.
- **Roster rotation**: live changes to the PKG roster via the
  config chain (006). The MVP takes the roster as static
  configuration.
- **Bloom-filter / incremental directory fetch**: the
  `directorySnapshot` returns the full directory. A production
  PKG with millions of identities needs partial-fetch
  primitives.
- **PKG operator tooling**: roster-key generation, audit logs,
  metrics, operator CLI.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A PKG with a 3-of-5 roster can issue 5 identities,
  and every issued identity is resolvable through
  `directorySnapshot().lookup(identity)` returning the expected
  bundle.
- **SC-002**: Identity issuance is deterministic given a
  fixed-seed RNG and a fixed-seed mailbox-id allocator. Two PKGs
  initialised with the same inputs and run through the same
  sequence of `issueIdentity` calls produce byte-identical
  directory snapshots.
- **SC-003**: Duplicate-identity issuance is rejected without
  mutating state (verify by issuing alice, attempting alice
  again, then issuing bob — bob succeeds, alice still has the
  original bundle).
- **SC-004**: Reserved mailbox-ids (0, -1) are never returned by
  `issueIdentity` even when the allocator's seed is contrived
  to suggest them.
- **SC-005**: One `issueIdentity` call completes in under 100 ms
  on a typical developer laptop (dominated by HybridOnion keygen
  + N ML-DSA sign calls).
- **SC-006**: A reviewer can confirm that `Pkg` carries NO
  long-lived references to issued bundles' SECRET halves — only
  the public halves and the proofs are retained for the
  directory. (The MVP's `issueIdentity` returns the secret to
  the caller; the PKG itself never stores it.)

## Assumptions

- Constitution v2.0.0 holds.
- Spec 012 (HybridOnion), 013 (PqSignature), 014's
  `MultiSignedEntry` primitive (from 015's PR), and 015
  (IdentityEncryption) are all on main.
- Spec 004 (mixnet-server) is on main; the PKG uses
  `MixChain.CoverMailboxId` and `BroadcastMailboxId` as the
  reserved values to skip during mailbox allocation.
- The PKG roster is configured at construction. Roster rotation
  via the config chain (006) is a follow-up integration.
- Identity strings are bytes, not UTF-8 strings. Display-name
  disambiguation and identity-policy concerns are
  application-layer (not crypto-layer).
- The PKG returns the issued `HybridSecretBundle` to the caller
  out-of-band. The actual delivery channel (TLS, in-person,
  signed email) is operational, not crypto-layer.
- The PKG never sees the user's plaintext messages — it only
  binds identities to public bundles.
- Privacy regression noted in spec 015 (PKG learns lookup
  patterns) still applies; spec 005's MVP doesn't mitigate it
  further (that's 007 SDK's mixnet-routed lookup).
