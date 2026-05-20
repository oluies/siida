# Feature Specification: Mixnet Server (Coordinator + Mixer Chain)

**Feature Branch**: `004-mixnet-server`

**Created**: 2026-05-20

**Status**: Draft — first cut. MVP focuses on a single-process,
synchronous mix chain runnable from tests; distributed
multi-process deployment + persistent state + crash recovery
are explicit non-goals of 004 and reserved for follow-up specs.

**Input**: Spec 012 shipped `HybridOnion` (the per-layer ciphertext
primitive). Spec 015 shipped `IdentityEncryption` (the
identity-addressed flow). Specs 013/014/017 shipped the signature
machinery underneath. The crypto stack is conformant and complete
through Q2-2026. This spec wires those primitives into the
mixnet's round-aligned batch protocol — the data plane that
delivers metadata privacy.

## Why this spec exists

Vuvuzela's mixnet is the load-bearing privacy mechanism:
N senders submit a layered onion per round; a chain of M mixers
each peel one layer and shuffle the batch; the final mixer
delivers `(mailbox_id, ciphertext)` pairs to recipients. The
metadata-privacy property derives from the shuffle: an observer
watching mixer-to-mixer traffic cannot link an output ciphertext
to its sender.

Siida derives from Vuvuzela but re-implements in Scala 3 with
PQ-safe primitives. Spec 004 codifies the **server-side runtime**:
the coordinator that orchestrates rounds, the mixer that peels-
and-shuffles, the wire formats between them, and a deterministic
test harness that runs the whole chain end-to-end in one JVM.

This spec deliberately scopes down to the **minimum viable
mixnet** — one round at a time, in-memory, with the core mixing
algorithm correct. Network protocols, persistent state, crash
recovery, and live operations are reserved for follow-up specs.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — A round mixes a batch end-to-end, recovering the right ciphertext-to-mailbox bindings (Priority: P1)

The MVP: a coordinator runs a round with N=8 client submissions
through a chain of M=3 mixers. Each submission is a
`MixChain.layeredSubmission` (N-layer onion). Each mixer peels
its layer, shuffles the batch (deterministic given a per-mixer
random seed), and forwards to the next mixer. The final output is
a set of N `(mailbox_id, inner_ciphertext)` pairs that recipients
can claim.

**Why this priority**: P1 because this IS the mixnet. Everything
else (round timing, network plumbing, observability) supports this
core algorithm.

**Independent Test**:
`./mill modules.mixnet.test --testOnly siida.mixnet.RoundSuite`
runs a fixture: 8 fixed-seed clients, 3 fixed-seed mixers, one
fully-deterministic round. The output mailbox-to-ciphertext set
matches the expected (computed by the test from the same seeds).

**Acceptance Scenarios**:

1. **Given** a roster of 3 mixers with stable public bundles and
   8 clients each holding a (mailbox_id, plaintext) pair,
   **When** each client submits its layered onion to the
   coordinator and the coordinator runs the round,
   **Then** the final mailbox-to-ciphertext set contains all 8
   entries with the right plaintexts after the recipient decrypts.
2. **Given** the same setup with one client's submission corrupted
   (e.g., the second layer's AEAD ciphertext flipped),
   **When** the coordinator runs the round,
   **Then** the corrupted submission is dropped at the mixer
   that fails to decrypt; the remaining 7 are delivered.
3. **Given** fixed-seed RNGs for clients and mixers,
   **When** the same round runs twice,
   **Then** the output mailbox set is byte-identical (up to
   shuffle permutation, which is also seed-determined).

### User Story 2 — Mixer integrity: a corrupt mixer can drop or duplicate but cannot decrypt (Priority: P1)

A mixer holds the private key for its layer of the onion. To
peel its layer it MUST decrypt, but it sees only its own layer's
plaintext — the inner layers remain encrypted. Specifically:
mixer #k decrypts to recover `(mailbox_id_or_next_layer,
inner_ciphertext)`, where `inner_ciphertext` is opaque to mixer
#k unless k is the final mixer.

**Why this priority**: P1 because this is the metadata-privacy
property: no single mixer learns who sent what. A corrupt mixer
can refuse to mix, drop submissions, or reorder them — these are
DoS or availability attacks but NOT confidentiality attacks.

**Independent Test**: The `MixerSuite` verifies that a mixer
holding only its own secret bundle CANNOT decrypt an
intermediate-layer ciphertext targeted at a different mixer.
Pure cryptographic test; reuses 012's HNDL pattern.

**Acceptance Scenarios**:

1. **Given** a 3-mixer round and a 1-layer-peeled ciphertext from
   mixer #2, **When** mixer #1 (holding mixer-#1's secret bundle)
   attempts to decrypt the wire bytes, **Then** decryption fails
   with `MixerError.DecapsulationFailed`.

### User Story 3 — Cover traffic: every client sends exactly one ciphertext per round (Priority: P2)

Per the Vuvuzela design, the metadata-privacy guarantee depends
on every client contributing exactly one submission per round —
either a real message or a "cover" message to a dummy mailbox.
The 004 MVP provides the `Client.coverSubmission(rng, round)`
helper; the SDK (spec 007) uses it.

**Why this priority**: P2 because the cover-traffic pattern is a
client-side discipline that the mixnet enforces only by uniform
batch processing (no special handling for cover vs real). The
test verifies that a cover submission and a real submission look
identical to a mixer.

**Independent Test**: A test fixture generates 4 real submissions
+ 4 cover submissions; the mixer chain processes the batch; the
mixer cannot distinguish them by any observable side channel.

**Acceptance Scenarios**:

1. **Given** a mixed batch of 4 real + 4 cover submissions,
   **When** mixer #1 processes the batch, **Then** all 8 wire
   envelopes have the same byte length and the same on-wire
   structure (1-byte alg-ID + 1137-byte HybridOnion overhead +
   payload). No fingerprint distinguishes them.

### Edge Cases

- **Empty round**: a round with zero submissions yields an empty
  output set; coordinator emits an empty round result, not an
  error. Spec 007's SDK is responsible for ensuring N submissions
  per round via cover traffic.
- **Mismatched chain length**: a client submits a 3-layer onion to
  a coordinator configured for a 4-mixer chain. The first mixer
  in the chain (#1) decrypts a layer that should still be the
  layer-2 ciphertext, fails to parse as a valid next-layer
  envelope, and drops the submission. Documented as "client
  responsibility" — the SDK uses the published chain definition
  from the config chain (006) to construct correctly-layered
  submissions.
- **Duplicate-mailbox collision**: two clients deliver to the same
  mailbox in the same round. The final mixer emits both; the
  recipient sees both entries when polling. The mailbox is just
  a routing key, not a uniqueness constraint.
- **Mixer key rotation**: the mixer's `HybridSecretBundle` is
  long-lived but rotates per epoch (config chain 006 controls).
  004 takes the mixer keys as configuration; rotation is the
  config-chain integration's concern.
- **Round number disambiguation**: each round has a 64-bit
  monotonic round number. Clients must include the round number
  in the innermost mailbox-id field so a stale resubmission to a
  later round is detectable. (004 surfaces the field; 007 SDK
  populates it.)

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The mixnet module MUST expose `siida.mixnet.api`
  with three core types:
  - `MixChain` — client-side layered-encryption helper
  - `Mixer` — peel-and-shuffle one layer
  - `Coordinator` — orchestrate a round across the mixer chain
- **FR-002**: A `Submission` is a single layered onion:
  N `HybridOnion.OnionLayer` envelopes, one per mixer in the
  chain, plus the innermost `(mailbox_id, inner_ciphertext)`
  payload. Wire format: opaque to 004 — `MixChain.encode` /
  `MixChain.decode` handle the framing.
- **FR-003**: `Coordinator.runRound(submissions, mixerKeys, seeds)`
  MUST be a **pure deterministic function** of its inputs. Given
  the same submissions + mixer secret bundles + per-mixer
  shuffle seeds, the same `RoundResult` is produced byte-for-byte.
  This is the contract that makes the system testable.
- **FR-004**: A mixer that fails to decrypt a layer MUST drop the
  submission silently — no error propagated, no fingerprint left
  in the output batch. The round continues with the remaining
  submissions.
- **FR-005**: The shuffle within each mixer MUST use a
  cryptographically random permutation seeded from a per-round
  per-mixer 32-byte seed. Deterministic given the seed (so tests
  are reproducible) but unpredictable to anyone without the seed.
- **FR-006**: The wire format between mixers MUST be exactly the
  `HybridOnion.OnionLayer` byte string — no per-mixer framing
  overhead. Each "hop" produces output bytes that are themselves
  valid `OnionLayer` envelopes (one layer thinner) until the
  final mixer's output, which is the innermost
  `(mailbox_id, inner_ciphertext)` payload format.
- **FR-007**: The cover-traffic pattern MUST be supported via
  `MixChain.coverSubmission(roster, rng)`: produces a submission
  to a dummy mailbox (e.g., mailbox_id = 0) with a random
  inner-ciphertext. Indistinguishable on-wire from a real
  submission.
- **FR-008**: Test fixtures MUST be deterministic under fixed-
  seed RNG (same FR pattern as 012/013/015).
- **FR-009**: The mixnet test suite MUST exercise the full
  round end-to-end on a 3-mixer / 8-client fixture and verify
  every plaintext-to-mailbox binding is recovered correctly.
- **FR-010**: API stability: the public Scala API of
  `siida.mixnet.api.{MixChain, Mixer, Coordinator}` is locked
  post-004 merge.

### Out-of-scope (deferred to follow-up specs)

The MVP intentionally does NOT include:

- **Network protocols** (TCP / gRPC / Pekko Remote) for
  client→coordinator or mixer→mixer transport. The Pekko Streams
  pipeline used internally is single-JVM. A follow-up spec wires
  network transport when the protocol surface stabilises.
- **Persistent state** for in-flight rounds. A 004-MVP crash
  during a round loses all submissions for that round.
- **Crash recovery / leader election** when a mixer goes down
  mid-round. A follow-up spec adds this; 004 assumes single-
  threaded happy path.
- **Live roster rotation** via the config chain. 004 takes the
  roster as a static parameter; rotation is the config-chain
  integration's concern (consumes 006 once that lands).
- **Distributed tracing / OpenTelemetry / Prometheus**. Deferred
  to spec 018 (observability).
- **Performance optimisation**: cores per round, batching across
  rounds, custom thread pools. The MVP focuses on correctness.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A 3-mixer / 8-client / 1-round fixture passes
  end-to-end: all 8 plaintexts arrive at the right mailboxes.
- **SC-002**: The round is deterministic — running it twice with
  the same fixed-seed inputs produces byte-identical
  `RoundResult` outputs.
- **SC-003**: A corrupted-by-tampering submission is dropped
  cleanly at the first mixer that can't decrypt it; the round's
  other 7 submissions still deliver.
- **SC-004**: A single round on a 3-mixer / 8-client / 256-byte-
  inner-payload fixture completes in under 500 ms on a typical
  developer laptop.
- **SC-005**: A reviewer can confirm by inspection that mixers'
  state is per-call only (no global mutable state) so the
  coordinator's `runRound` IS a pure function modulo crypto.
- **SC-006**: Total module test count for `modules.mixnet.test`
  goes from 1 (placeholder) to at least 8 covering happy-path
  + tamper + cover + serialisation properties.

## Assumptions

- Constitution v2.0.0 holds.
- Specs 012, 013, 014, 015, 017 all merged — the crypto layer is
  FIPS-conformant and complete.
- Pekko Streams 1.1.5 is the in-process pipeline abstraction
  (already in `Versions.pekko` from spec 001's build).
- The cryptographic shuffle is `random permutation` driven by a
  per-round per-mixer fresh 32-byte seed — NOT a verifiable
  shuffle. Vuvuzela's original design also doesn't use verifiable
  shuffles; the security model is "honest-but-curious mixer for
  metadata-privacy; verifiable-shuffle is overkill at the
  Vuvuzela threat model."
- 004 takes the mixer chain definition (list of mixer public
  bundles, in chain order) as a static configuration parameter.
  Rotation is spec 006's responsibility.
- The mailbox-id space is 64-bit unsigned integers. Spec 005
  (PKG) and spec 007 (SDK) own the mailbox-assignment scheme.
- Onion routing is non-replay-resistant by design: a replayed
  submission produces the same path and the same delivery.
  Replay protection is the mailbox holder's concern (e.g., via
  round-number checks in the inner payload).
- No cover-message decryption test — cover submissions deliver to
  a dummy mailbox; the cover-mailbox holder is the PKG (spec 005)
  which discards them. 004 just confirms cover submissions go
  through the chain successfully.
