---
description: "Task list for 019-friend-discovery (MVP)"
---

# Tasks: Friend Discovery (Add-Request MVP)

**Input**: Design documents from `/specs/019-friend-discovery/`

**Prerequisites**: spec.md, plan.md, research.md, contracts/.
Specs 012, 013, 014, 015, 005 are on main; 019 builds on them.

**Tests**: Build/process/verify happy paths, impersonation
rejection, tamper rejection, alg-ID refusal, FriendStore
semantics, wire-format size.

---

## Phase 1: Setup

- [X] T001 No new module deps. PKG already depends on crypto
  (since spec 005). _(done)_

---

## Phase 2: Foundational

- [X] T002 [P] Extend `modules/pkg/src/siida/pkg/api/Errors.scala`
  with `enum FriendshipError derives CanEqual` covering
  `InvalidLength`, `UnsupportedAlgorithm`, `DecryptionFailed`,
  `MalformedRequest(reason)`, `IdentityNotInDirectory`,
  `IdentityMismatch`. _(done)_
- [X] T003 [P] Write
  `modules/pkg/src/siida/pkg/api/AddRequestWire.scala`:
  encode/decode for the inner-plaintext payload (2-byte BE
  identity length + identity bytes + 1216-byte HybridPublicBundle
  serialisation). Total: 1218 + identity_len bytes. _(done)_

---

## Phase 3: User Story 1 — alice → bob add-request happy path (Priority: P1)

- [X] T004 [US1] Write `modules/pkg/src/siida/pkg/api/Friendship.scala`:
  - opaque type `AddRequest`
  - `AlgorithmID.AddRequest_v1 = 0x30`
  - `AddRequestContent` case class
  - `buildAddRequest` — encode payload + HybridOnion.encrypt +
    prefix alg-ID
  - `processAddRequest` — strip alg-ID + HybridOnion.decrypt +
    decode payload; all failures collapse to FriendshipError
  - `verifyAddRequest` — directory lookup + bundle equality
    check (the load-bearing SC-006 trust step)
  - `serialiseAddRequest` / `deserialiseAddRequest` with uniform
    alg-ID refusal (FR-007)
  _(done; 8/8 FriendshipSuite tests pass)_
- [X] T005 [US1] Write `modules/pkg/test/src/FriendshipSuite.scala`
  with 8 tests: build → process recovery (SC-001), verify success
  on matching binding, forgery rejection (SC-002), unknown sender
  (IdentityNotInDirectory), tampered ciphertext (SC-003),
  unknown alg-ID (FR-007), too-short input (InvalidLength), and
  wire-format size assertion. _(done; all green)_

---

## Phase 4: User Story 2 — Forgery rejection (Priority: P1)

- [X] T006 [US2] Covered by FriendshipSuite test "forgery: carol
  claims to be alice but uses her own public bundle →
  IdentityMismatch" — the load-bearing SC-006 property:
  verifyAddRequest consults ONLY the directory, never the
  self-claim. _(done)_

---

## Phase 5: User Story 3 — FriendStore (Priority: P2)

- [X] T007 [US3] Write
  `modules/pkg/src/siida/pkg/api/FriendStore.scala`:
  trait + `inMemory()` factory backed by LinkedHashMap with
  ArraySeq-wrapped keys for structural equality. `add` returns
  Boolean (true = newly added, false = idempotent re-add).
  `lookup` returns `Option[HybridPublicBundle]`. `list`
  enumerates in insertion order. _(done)_
- [X] T008 [US3] Write `modules/pkg/test/src/FriendStoreSuite.scala`
  with 5 tests: empty-store sanity, add→lookup, idempotent
  re-add preserves original bundle, list-in-insertion-order,
  structural-bytes lookup (fresh array, same bytes). _(done; all
  green)_

---

## Phase N: Polish & Cross-Cutting

- [X] T009 Run `make check` end-to-end; expect green. _(EXIT=0)_
- [X] T010 [P] Confirm PKG module test count: 13 (post-005) →
  26 (post-019, +5 FriendStore +8 Friendship). _(confirmed)_
- [X] T011 [P] Update `README.md` roadmap with the 019 slot
  inserted between 018 and the next-future-slot. _(done in same
  PR)_

---

## Dependencies

- Phase 1 setup is a no-op
- Phase 2 foundational utilities block US1/US2/US3
- US1 + US2 + US3 can run in parallel after Phase 2
- Polish runs after all stories

## Notes

- **019 ships the add-request half only.** The add-response /
  friendship-key derivation half (bob → alice acknowledgement +
  shared-secret derivation) is a follow-up spec.
- **Mixnet routing is out-of-scope** — the SDK (spec 007) will
  compose `Friendship.buildAddRequest` with
  `MixChain.layeredSubmission`. 019 produces the ciphertexts;
  the SDK puts them through the wire.
- **Friendship-key dial tokens** (Alpenhorn's PKG-side
  optimisation) are deferred. The MVP's FriendStore is
  local-only; lookups still flow to the PKG on cache miss.
- **The SC-006 verification property is load-bearing.**
  `verifyAddRequest` MUST consult ONLY the directory, never the
  claimed bytes' self-attestation. This is what blocks
  impersonation attacks (US2).
- **Replay protection is absent in the MVP.** A recorded
  add-request can be re-decrypted; the FriendStore catches the
  duplicate via idempotent `add`. Nonce-based replay protection
  is a follow-up if needed.
- **FriendStore is in-memory only.** Encrypted-at-rest
  persistent storage is a follow-up.
- **No revocation / unfriend / block-list** in the MVP.
