# Feature Specification: Friend-Discovery Follow-Ups

**Feature Branch**: `020-friend-discovery-followups`

**Created**: 2026-05-20

**Status**: Draft (MVP)

## Why this spec exists

Spec 019 shipped the **add-request half** of Alpenhorn-style friend
discovery (alice → bob): build, process, verify. Three follow-ups
were deferred for later work. This spec ships the smallest viable
versions of each:

1. **Add-response half** (US1): bob acknowledges alice and shares a
   small ack payload so alice's SDK can finalise the friendship
   state.
2. **Friendship-key derivation** (US2): both parties deterministically
   compute the same per-friendship key from public bundles + an
   `ad_id` (an Alpenhorn-style "add-id" both share). Replaces (for the
   MVP) Alpenhorn's IBE-based per-epoch dial tokens; no PKG consult
   after discovery.
3. **Persistent FriendStore** (US3): on-disk file-based persistence
   for the in-memory friend store from 019, so a client survives a
   restart without re-running discovery against everyone.

## User Scenarios

### US1 — bob → alice add-response (P1)

After bob's `processAddRequest` + `verifyAddRequest` succeed, he
calls `Friendship.buildAddResponse(addReqContent, recipientBundle=
alice.publicBundle, ackPayload, rng)`. The result is an
`AddResponse` ciphertext alice can decrypt via
`processAddResponse(secretBundle, addResponseBytes)` to recover
`AddResponseContent(senderIdentity, ackPayload)`. Alice's SDK
records bob in her FriendStore.

**Acceptance**:
1. processAddResponse recovers the (sender identity, ack payload).
2. Tampered ciphertext → `DecryptionFailed`.
3. Unsupported alg-ID byte → `UnsupportedAlgorithm`.
4. Too-short input → `InvalidLength`.

### US2 — Deterministic friendship key (P1)

`Friendship.deriveFriendshipKey(my=alice.publicBundle,
their=bob.publicBundle, adId)` returns a 32-byte symmetric secret.
The function is deterministic and order-independent in its two
public arguments (the byte-pair is sorted before hashing) so alice
and bob always derive the same key.

Algorithm: `SHA3-256( DST || min(serialised_a, serialised_b) ||
max(serialised_a, serialised_b) || adId )` with
`DST = "siida/friendship/v1/key"`.

**Acceptance**:
1. Symmetric: `deriveFriendshipKey(a, b, id) == deriveFriendshipKey(b, a, id)`.
2. Deterministic across runs.
3. Different `adId` values produce different keys for the same pair.
4. Output length = 32 bytes.

### US3 — Persistent FriendStore (P2)

`FriendStore.persistent(path)` returns a store backed by a single
file at `path`. The wire format is a length-prefixed run of
`(identity_len: uint16-BE, identity_bytes, bundle_bytes 1216)`
records. `add` appends + fsyncs; `lookup` consults the in-memory
mirror; the file is loaded on construction.

**Acceptance**:
1. Add → close store → open new store at same path → lookup
   recovers the original bundle bit-exactly.
2. Insertion order is preserved across restart.
3. Concurrent opens are NOT supported (single-writer).

### Edge cases

- **Add-response without preceding add-request**: the protocol can't
  prevent this — bob can build a response to anyone whose public
  bundle he has. Alice's SDK is expected to drop responses whose
  sender identity isn't in her pending-outbound set; this is a
  client-layer concern (not 020's API surface).
- **adId reuse**: if alice and bob run discovery a second time with
  the same adId, they get the same friendship key. Caller is
  responsible for generating a fresh adId per discovery attempt;
  the MVP doesn't validate.
- **Persistent store with corrupt file**: load returns an error and
  refuses to construct; caller decides whether to delete and start
  fresh.

## Functional Requirements

- **FR-001**: `Friendship.buildAddResponse(senderIdentity, ackPayload,
  recipientPublicBundle, rng)` MUST produce an opaque `AddResponse`
  encrypted to the recipient bundle via `HybridOnion.encrypt`,
  prefixed with the algorithm ID `0x31` (reserved space).
- **FR-002**: `Friendship.processAddResponse(recipientSecret, response)`
  MUST collapse every failure mode (decryption, alg-ID, length,
  malformed payload) into `FriendshipError` per existing 019
  conventions.
- **FR-003**: `Friendship.deriveFriendshipKey` MUST be symmetric:
  sort the two serialised public bundles before hashing.
- **FR-004**: `FriendStore.persistent(path)` MUST atomically rewrite
  the file on each `add` (write-tmp + rename) — partial writes from
  a crash mid-add MUST NOT corrupt the existing store.
- **FR-005**: Wire format of persistent store records: 2-byte BE
  identity length + identity bytes + 1216 bytes serialised
  HybridPublicBundle. The file MUST start with a 4-byte magic
  `0x53494644` (`"SIFD"`).

## Success Criteria

- **SC-001**: alice → bob full add-flow (add-request, response,
  store) end-to-end test passes deterministically.
- **SC-002**: Friendship-key symmetry test: 1000 random pairs all
  satisfy `deriveFriendshipKey(a, b, id) == deriveFriendshipKey(b, a, id)`.
- **SC-003**: Persistent store survives restart: add ≥ 3 friends,
  re-open store, list() returns them in insertion order.

## Algorithm-ID space

- 0x30 — `Friendship.AddRequest_v1` (assigned in 019)
- **0x31 — `Friendship.AddResponse_v1`** (assigned here)
- 0x32 — Friendship key dial-token (reserved; not yet used; the MVP
  uses `deriveFriendshipKey` instead)
- 0x33–0x3F — future friend-discovery extensions

## Out of scope

- Full Alpenhorn dial tokens (per-epoch, PKG-issued).
- Revocation / unfriend / block list.
- Network transport for responses (the SDK from 007 wraps these
  into MailboxEnvelope + mixnet routing).
- Garbage collection / compaction of the persistent store's append-only file.
- Encryption-at-rest of the persistent store (a future spec; currently the bundles are public anyway).

## Dependencies

- 012 HybridOnion (encrypt/decrypt for the AddResponse layer)
- 019 Friendship (AddRequest, AddRequestContent — symmetry with new types)
