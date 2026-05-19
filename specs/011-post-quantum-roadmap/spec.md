# Feature Specification: Post-Quantum Cryptography Roadmap

**Feature Branch**: `011-post-quantum-roadmap`

**Created**: 2026-05-19

**Status**: Draft — roadmap spec, not a single implementation feature

**Input**: User direction: "Open a post-quantum roadmap spec. Prefer
European-certified PQ schemes, with a preference for Swedish-
affiliated work where the choice is otherwise neutral."

## Why this spec exists

Spec 002 locked in BN254 pairing-based cryptography (Boneh-Franklin
IBE, BLS signatures) — primitives whose security rests on the
hardness of the Elliptic Curve Discrete Log Problem and the
Bilinear Diffie-Hellman assumption. **Both are broken by Shor's
algorithm on a sufficiently large quantum computer.** Siida's IBE-
encrypted ciphertexts are vulnerable to *harvest-now-decrypt-later*
adversaries from the moment they leave a sender's machine.

The constitution v1.0.0 (Principle I) places metadata privacy at
the centre of Siida's threat model. A quantum-capable adversary
could:

- Retroactively decrypt every IBE-encrypted message ever sent
- Retroactively forge signatures in the config chain (005),
  including PKG rotation attestations
- Compromise the NaCl `box` onion layers, undoing the mixnet's
  metadata protection

This spec does not implement any post-quantum (PQ) primitive. It
establishes the roadmap: threat-model amendment, scheme catalogue,
per-primitive replacement decisions, phased migration, and
European-certification anchoring.

## User Scenarios & Testing *(mandatory)*

This is a roadmap spec rather than a feature spec, so "user
stories" are read as "decisions the roadmap commits to."

### User Story 1 - Amend the constitution's threat model to include quantum adversaries (Priority: P1)

A future contributor opening any spec from 012 onward needs the
constitution to be clear that quantum adversaries are in scope, so
they can reject pairing-based primitives or BSL-equivalent
classical-only choices at the Constitution Check gate. The
constitution today (Principle I, Security & Threat Model section)
mentions a "global passive adversary plus minority of compromised
mixers / PKGs" — quantum capability is silent.

**Why this priority**: Without this amendment, future specs would
either litigate the threat model anew or quietly assume classical
adversaries, propagating the existing PQ-blind assumptions.

**Independent Test**: The constitution PR that this spec generates
extends Principle I to enumerate quantum capability explicitly, and
adds a Security & Threat Model section paragraph stating the
harvest-now-decrypt-later concern. The version bumps from 1.0.x
to 2.0.0 (MAJOR) per the constitution's versioning policy.

**Acceptance Scenarios**:

1. **Given** the current constitution v1.0.0, **When** a contributor
   reads Principle I, **Then** quantum adversaries are NOT mentioned.
2. **Given** the post-011 constitution v2.0.0, **When** the same
   contributor reads Principle I, **Then** quantum adversaries are
   explicit, the harvest-now-decrypt-later concern is documented,
   and the migration roadmap (this spec) is linked.

### User Story 2 - Lock per-primitive PQ replacement choices (Priority: P1)

Each Siida cryptographic primitive needs a documented PQ
replacement plan so that future implementation specs (per-primitive
migration features) can be written without re-doing the scheme
analysis.

**Why this priority**: Per-primitive choices are not independent
(KEM + signature choices affect protocol shape together). Locking
them in one place avoids accidental fragmentation across migration
specs.

**Independent Test**: For each current Siida primitive (IBE, BLS
signatures, NaCl `box` ECDH, scalar randomness), the research
document records: chosen PQ replacement, the European certification
anchor (BSI / ANSSI / ENISA / SI3000 / FRA), Swedish-research
provenance where applicable, and the migration phase (hybrid first,
PQ-only later).

### User Story 3 - Define migration phases (Priority: P2)

Migration cannot be a flag day; Siida ships incrementally. The
roadmap commits to a phased plan with explicit "hybrid" interim
states (classical + PQ in parallel) before PQ-only cutover.

**Why this priority**: P2 because the per-primitive choices (US2)
are the hard part; phasing is operational scaffolding once the
choices are made.

**Independent Test**: For each per-primitive replacement (US2), the
research document records the migration phases (hybrid handshake,
PQ-only handshake, ciphertext-format version), the wire-format
versioning approach, and the deprecation criteria.

### Edge Cases

- **A primitive has no production-grade PQ equivalent** (e.g., IBE
  in its full Boneh-Franklin shape): the roadmap MUST document
  whether to (a) wait for research maturation, (b) substitute a
  protocol-level redesign that uses PQ KEMs + identity management,
  or (c) accept residual quantum risk for that primitive.
- **A scheme's status changes between roadmap and implementation**
  (e.g., NIST withdrawal of a finalist, BSI changing guidance): the
  per-primitive spec amending the choice MUST cite the current
  guidance at implementation time and bump the constitution if the
  change is material.
- **European certification lags ENISA / NIST** for a chosen scheme:
  the roadmap MUST document the fallback (classical-only until
  certification, or pre-certification deployment with documented
  acceptance of regulatory risk).
- **Hybrid mode adversary attacks**: a hybrid handshake's security
  is `min(classical security, PQ security)` if naively combined;
  the roadmap MUST specify the combiner construction (typically
  hashing both shared secrets together with a domain-separation
  tag).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: A constitution amendment MUST be drafted as part of
  this spec's deliverables, extending Principle I (Metadata Privacy
  is Non-Negotiable) and the Security & Threat Model section to
  state that quantum adversaries are in scope from a defined date
  forward.
- **FR-002**: The amendment MUST bump the constitution version to
  2.0.0 per the constitution's own versioning policy (MAJOR =
  backward-incompatible redefinition of a principle).
- **FR-003**: For each current Siida cryptographic primitive (IBE,
  BLS signatures, BLS proofs-of-possession, NaCl `box` onion layer,
  scalar randomness, BN254 pairing in non-IBE/BLS uses), the
  research document MUST record:
  - Current scheme and the security assumption that quantum breaks
  - Chosen PQ replacement scheme name
  - European certification anchor: which agency endorses it, and at
    what level (BSI TR-02102-1, ANSSI recommendation, ENISA report,
    or pending)
  - Swedish-affiliated research lineage if any (Lund University, KTH,
    FRA, RISE) — used as a tie-breaker when multiple schemes are
    equivalent on other criteria
  - Migration phase (hybrid first, PQ-only later)
- **FR-004**: PQ scheme choices MUST prefer European-certified
  options. Where no European certification exists yet, the roadmap
  MUST prefer schemes whose design teams include at least one
  European institution.
- **FR-005**: The roadmap MUST identify which primitives have NO
  production-grade PQ replacement available (notably:
  Boneh-Franklin IBE has no widely-deployed PQ analogue) and
  document the protocol-level alternative path (e.g., PQ KEM +
  identity-managed-at-the-PKG-layer).
- **FR-006**: The roadmap MUST commit to a hybrid-first migration
  phase for every primitive that touches the wire format (onion
  layers, config-chain signatures, signed PKG updates). PQ-only
  cutover is a per-primitive follow-up spec, not part of 011.
- **FR-007**: The roadmap MUST list the per-primitive implementation
  specs it spawns (e.g., "012-pq-mixnet-onion-layer", "013-pq-bls-
  replacement", etc.), with each new spec slot reserved so the
  numbering is monotonic.
- **FR-008**: Wire-format versioning MUST be considered: every
  cryptographic envelope in Siida MUST carry a version byte or
  algorithm identifier so a hybrid-to-PQ-only transition is
  detectable per-message without a global flag day.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The constitution amendment lands with the version
  bumping from 1.0.x to 2.0.0; downstream specs (002 already merged,
  005-009 in flight) record this as a known-incoming amendment.
- **SC-002**: A reviewer reading `research.md` can answer "what
  replaces the IBE on the PQ side" in under 60 seconds.
- **SC-003**: Every primitive currently used by Siida has a row in
  the per-primitive replacement table in `research.md`.
- **SC-004**: For each PQ replacement choice, a European
  certification source is cited (or the lack of one is documented).
- **SC-005**: At least one Swedish-affiliated research source is
  cited for at least three of the per-primitive choices, used as a
  tie-breaker where applicable.
- **SC-006**: The number of new spec slots reserved by this roadmap
  is finite and listed; "012-pq-mixnet-onion-layer" through whatever
  the highest number is. The README roadmap table is updated to
  show them as "sketched."

## Assumptions

- The constitution v1.0.0 stack pins (Scala 3, Pekko, Cats Effect 3,
  Mill, JDK 21 LTS) hold throughout PQ migration. PQ work is
  cryptographic, not language-level.
- Hybrid PQ + classical schemes are the realistic deployment shape
  for at least a 5-year window; PQ-only cutover happens per
  primitive based on confidence in the PQ assumption maturing.
- NIST FIPS 203 (ML-KEM, ex-Kyber) and FIPS 204 (ML-DSA, ex-
  Dilithium) are the most-vetted PQ schemes as of 2026-05-19;
  European agencies (BSI, ANSSI) endorse them under their own
  certification regimes (BSI TR-02102-1 for ML-KEM and ML-DSA, both
  expected to be added).
- Swedish PQC research is real (Lund University, KTH, RISE Research
  Institutes of Sweden) but Sweden does not maintain its own
  national PQ certification scheme separate from ENISA / BSI; the
  preference therefore expresses as "schemes with documented Swedish
  research contributions" rather than "schemes certified by a
  Swedish agency."
- Boneh-Franklin IBE has no production-grade PQ analogue. Lattice-
  based IBE schemes exist in research (GGH-based, Agrawal-Boneh-
  Boyen) but none are NIST/BSI-standardised. The roadmap accepts
  that the IBE replacement is a *protocol redesign*, not a *drop-in
  swap*.
- A future spec amending the constitution to add quantum
  adversaries to Principle I is required before per-primitive PQ
  migration specs can pass their Constitution Check gate.
