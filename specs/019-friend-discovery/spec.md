# Feature Specification: Friend Discovery (Alpenhorn Add-Request)

**Feature Branch**: `019-friend-discovery`

**Created**: 2026-05-20

**Status**: Draft — MVP for the cryptographic primitive only.
Mixnet routing of add-requests, cover-add-traffic per-round
discipline, friendship-key dial tokens, and full SDK integration
are explicit non-goals of 019; they live in spec 007 (client SDK)
or as follow-up specs.

**Input**: Spec 005 (PKG) MVP shipped identity issuance but
deferred friend-discovery — the Alpenhorn-style add-request
protocol that lets one identity learn another's public bundle in
a privacy-preserving way. The 005 roadmap entry explicitly
mentioned "...and friend-discovery primitives" as a follow-up.
019 picks that up.

## Why this spec exists

Spec 015's PKG-directory + HybridOnion design solves the
identity-addressed encryption flow: alice can encrypt to bob if
she knows bob's identity string. But how does alice **learn**
bob's identity in the first place, in a way that doesn't leak
their friendship to the PKG on every interaction?

The Alpenhorn answer (Lazar & Zeldovich, OSDI 2016): an **add-
request protocol** routed through the mixnet. Alice constructs
a ciphertext containing her own identity + public bundle, and
encrypts it to bob's bundle. Bob receives it (via his mailbox),
decrypts, and decides to accept the friendship. Once accepted,
both sides hold each other's public bundles in their local
friend store — no further PKG lookups needed for that pair.

The cryptographic primitive is small and clean: it reuses
`HybridOnion.encrypt` from spec 012 for the encryption itself.
The interesting work is in (a) the wire format of the add-request
payload, (b) the verification step (recipient confirms the
sender's claimed identity via the PKG directory), and (c) the
friend-store data structure.

The mixnet-routing concerns — cover-add-traffic per round,
add-request submission timing, retry logic, dropped-friend
recovery — are the SDK's (spec 007's) responsibility. 019 ships
the building blocks; 007 composes them into the user-facing
flow.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Alice constructs an add-request to bob; bob decrypts and verifies (Priority: P1)

A new user, alice, wants to befriend bob. She:

1. Fetches bob's `HybridPublicBundle` from her local
   `Directory` snapshot (provided by the PKG, spec 005)
2. Constructs an `AddRequest` ciphertext containing alice's
   own identity + her public bundle, encrypted to bob's bundle
3. Sends the ciphertext to bob's mailbox (out-of-scope: mixnet
   routing)

Bob, polling his mailbox:

1. Receives the ciphertext
2. Calls `Friendship.processAddRequest(bobSecret, ct)` → gets
   the claimed `(senderIdentity, senderPublicBundle)` content
3. Verifies the binding via his own directory snapshot:
   `Friendship.verifyAddRequest(content, directory)` confirms
   that "alice@siida" really does resolve to `senderPublicBundle`
4. If verified, bob adds alice to his local `FriendStore`

**Why this priority**: P1 because this is the load-bearing
"how to befriend someone privately" flow. Without it, the
PKG-directory model alone leaks every (sender, recipient) pair
to the PKG via the lookup pattern.

**Independent Test**: A fixture with a PKG + 3 issued identities
(alice, bob, carol) runs the full add-request flow alice → bob,
then verifies bob's friend store now contains alice.

**Acceptance Scenarios**:

1. **Given** alice and bob each have HybridSecretBundles from
   the PKG and bob's directory snapshot,
   **When** alice calls `Friendship.buildAddRequest(...)` to bob
   and bob calls `Friendship.processAddRequest(...)`,
   **Then** bob recovers alice's claimed identity and public
   bundle byte-for-byte.
2. **Given** bob has the recovered content,
   **When** bob calls `Friendship.verifyAddRequest(content,
   directory)`,
   **Then** verification returns `Right(())` because the
   directory binds alice's identity to that exact public bundle.
3. **Given** the same setup but with alice's public bundle in
   the request swapped for carol's,
   **When** bob calls `verifyAddRequest`,
   **Then** the result is `Left(FriendshipError.IdentityMismatch)`.

### User Story 2 — Forgery attempt: carol cannot impersonate alice (Priority: P1)

If carol (or any third party) constructs an add-request claiming
to be alice (using alice's identity string but carol's own
public bundle), bob's `verifyAddRequest` step MUST reject it.
This is the load-bearing security property of the protocol: the
PKG-directory binding gives bob ground truth about which public
bundle belongs to which identity.

**Why this priority**: P1 because impersonation is the obvious
attack. Without verification, the protocol is meaningless.

**Independent Test**: Carol constructs an add-request to bob
claiming `senderIdentity = "alice@siida"` but with her own
public bundle. Bob's `verifyAddRequest` returns
`Left(IdentityMismatch)`.

**Acceptance Scenarios**:

1. **Given** carol holds carol's secrets only,
   **When** carol calls `Friendship.buildAddRequest("alice@siida",
   carolPublicBundle, bobPublicBundle, rng)` and sends to bob,
   **Then** bob's `processAddRequest` succeeds (the ciphertext
   is valid — it's addressed to bob), but `verifyAddRequest`
   FAILS with `IdentityMismatch` because the directory binds
   "alice@siida" to alicePublicBundle, not carolPublicBundle.

### User Story 3 — Friend store: bob lists his accepted friends (Priority: P2)

Once bob accepts alice's add-request, alice's identity + public
bundle land in bob's `FriendStore`. Bob can later look up alice
by identity and encrypt to her without re-fetching the PKG
directory.

**Why this priority**: P2 because the friend-store is the
practical consequence of the protocol. Without it, every
interaction round-trips to the PKG anyway, defeating the privacy
goal.

**Independent Test**: After alice → bob add-request succeeds,
`bob.friendStore.lookup("alice@siida".getBytes)` returns
`Some(alicePublicBundle)`. `bob.friendStore.list()` includes
"alice@siida".

**Acceptance Scenarios**:

1. **Given** bob's friend store is empty,
   **When** bob accepts an add-request from alice via the flow
   described in US1,
   **Then** `bob.friendStore.lookup("alice@siida".getBytes)`
   returns `Some(alicePublicBundle)`.
2. **Given** the same state,
   **When** the SDK (out-of-scope, future spec) wants to encrypt
   from bob to alice,
   **Then** it can call `bob.friendStore.lookup` instead of
   `directory.lookup` — saving a PKG round-trip and (more
   importantly) not revealing the alice-bob friendship to the
   PKG on every interaction.

### Edge Cases

- **Replay attack**: a recorded add-request ciphertext can be
  resubmitted to bob. The ciphertext is the same; bob's
  `processAddRequest` succeeds again with the same content. Bob
  must rely on his FriendStore to detect the duplicate ("alice
  is already a friend"). 019 surfaces the duplicate via the
  FriendStore semantics; nonce-based replay protection is a
  follow-up.
- **Bob receives a tampered ciphertext**: AEAD decryption fails;
  `processAddRequest` returns `Left(DecryptionFailed)`. Standard
  HybridOnion error inheritance.
- **Sender's identity in the payload doesn't match any directory
  entry**: `verifyAddRequest` returns `Left(IdentityNotInDirectory)`.
  Could be a fresh identity not yet propagated to bob's snapshot;
  the SDK (007) decides whether to fetch a fresher snapshot and
  retry.
- **Duplicate add-request (alice asks bob again after being
  accepted)**: bob's FriendStore already contains alice;
  application-layer decision. The FriendStore returns `false`
  from `add` if the friend was already present, but doesn't
  treat re-adding as an error.
- **Multiple friend stores per identity**: the MVP holds one
  store per identity (per process). Persisting the store across
  process restarts is out-of-scope.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The PKG module MUST expose
  `siida.pkg.api.Friendship` with:
  - `buildAddRequest(senderIdentity, senderPublicBundle,
    recipientPublicBundle, rng): AddRequest`
  - `processAddRequest(recipientSecret, ct):
    Either[FriendshipError, AddRequestContent]`
  - `verifyAddRequest(content, directory):
    Either[FriendshipError, Unit]`
  - `serialiseAddRequest` / `deserialiseAddRequest`
  - `AlgorithmID.AddRequest_v1: Byte = 0x30`
- **FR-002**: An `AddRequest` ciphertext wraps a HybridOnion
  encryption of the `AddRequestPayload` plaintext. Wire format:
  1-byte alg-ID (0x30) followed by the HybridOnion.OnionLayer
  wire bytes.
- **FR-003**: The `AddRequestPayload` plaintext binds
  `(senderIdentity, senderPublicBundle)` together. Wire format
  per `contracts/wire-format.md`.
- **FR-004**: `verifyAddRequest` MUST compare the claimed
  `senderPublicBundle` against the directory's binding for
  `senderIdentity`. Mismatch → `Left(IdentityMismatch)`.
  Identity not in directory → `Left(IdentityNotInDirectory)`.
- **FR-005**: The PKG module MUST expose
  `siida.pkg.api.FriendStore` as a trait, plus an
  in-memory factory `FriendStore.inMemory()`. The trait surface:
  - `add(identity, publicBundle): Boolean` (returns false if
    already present)
  - `lookup(identity): Option[HybridPublicBundle]`
  - `list(): Seq[Array[Byte]]`
- **FR-006**: All `processAddRequest` failures collapse to typed
  `FriendshipError`s — no throws on per-call failures.
- **FR-007**: Algorithm-ID rejection on `deserialiseAddRequest`
  MUST be uniform per the same constant-timing discipline as
  013 / 014 / 015 / 005.
- **FR-008**: Test fixtures MUST be deterministic.
- **FR-009**: API stability (same pattern as prior specs).
- **FR-010**: No mixnet routing or transport in 019's scope.
  The SDK (spec 007) composes `MixChain.layeredSubmission` with
  the `AddRequest` bytes as the inner mailbox-envelope payload.

### Out-of-scope (deferred to follow-up specs)

- **Mixnet routing** of add-requests — the SDK (spec 007) handles
  the wire-level submission, cover-add-traffic per round, and
  retry. 019 produces the ciphertexts that the SDK puts into
  `MixChain.layeredSubmission`.
- **Cover add-traffic** discipline (always-send-an-add-request-per-
  round) — SDK concern.
- **Add-response / friendship-key exchange** — Alpenhorn's full
  protocol completes with bob sending a half-friendship-key back
  to alice; 019 ships only the alice → bob direction (the
  "I want to befriend you" half). A future spec adds the
  acknowledgement + shared-secret derivation.
- **Friendship-key dial tokens** — Alpenhorn's optimisation
  where future PKG lookups go through a per-pair token rather
  than identity strings. The MVP's `FriendStore` is local-only
  (no PKG-side dial-token registration); identity-string lookups
  still flow to the PKG when the SDK hits a friend-store miss.
- **Persistent FriendStore** — in-memory only; restart loses
  friendships.
- **Friendship revocation / unfriend** — separate spec.
- **Block-list / harassment defence** — separate spec.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A full alice → bob add-request flow succeeds
  (build → process → verify) using a PKG-issued directory; the
  recovered content matches alice's identity and public bundle
  byte-for-byte.
- **SC-002**: An impersonation attempt by carol (claiming to be
  alice but using carol's public bundle) is rejected by
  `verifyAddRequest` with `Left(IdentityMismatch)`.
- **SC-003**: A tampered add-request ciphertext fails decryption
  uniformly — `Left(DecryptionFailed)` per FR-006.
- **SC-004**: An unknown-algorithm-ID add-request is rejected
  with `Left(UnsupportedAlgorithm)` per FR-007.
- **SC-005**: One `buildAddRequest` + `processAddRequest` round-
  trip completes in under 100 ms on a typical developer laptop
  (dominated by HybridOnion encrypt+decrypt).
- **SC-006**: A reviewer can confirm that `verifyAddRequest`
  uses ONLY the directory's binding — not the claimed-identity-
  string-decoded-from-the-ciphertext — to make the trust
  decision. (No "alice trusts her own ciphertext" anti-pattern.)

## Assumptions

- Constitution v2.0.0 holds.
- Specs 012, 013, 014, 015, 005 are on main. The PKG-directory
  is the trust root; this spec leverages it.
- The SDK (spec 007) will route add-requests through the mixnet
  in production. 019's tests use in-process direct encrypt-
  decrypt; mixnet integration is a follow-up.
- Identity strings are bytes, not UTF-8. The protocol doesn't
  impose encoding.
- The PKG directory is assumed up-to-date at verification time.
  Stale-snapshot semantics (bob's snapshot doesn't yet contain
  freshly-issued alice) yield `IdentityNotInDirectory`; the SDK
  handles refresh.
- The recipient's secret bundle is held by the recipient out-of-
  band (delivered by the PKG at issuance time, per spec 005).
  19 does not handle key delivery.
- This is the **add-request** half only; the add-response /
  friendship-key derivation half is a follow-up spec.
