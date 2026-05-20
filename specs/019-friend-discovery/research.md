# Phase 0 Research: Friend Discovery

**Feature**: [spec.md](./spec.md)
**Date**: 2026-05-20
**Status**: Complete

## R1. Alpenhorn add-request protocol

Alpenhorn (OSDI 2016) divides friend-discovery into three
sub-flows:

1. **Add request**: alice → bob, "I want to be your friend.
   Here's my identity + public bundle. Will you accept?"
2. **Add response**: bob → alice, "Accepted. Here's my half of
   our friendship-key seed."
3. **Friendship-key derivation**: alice + bob each combine
   their seed-halves into a shared dial token registered with
   the PKG. Future lookups for either party go through the dial
   token, hiding the identity-string from the PKG.

019's MVP ships **only the first sub-flow** (alice → bob's
add-request). The add-response and friendship-key derivation are
deferred to follow-up specs. Rationale: each sub-flow is
self-contained at the crypto layer; shipping the first one is
useful on its own (it gives alice a way to introduce herself),
and the follow-ups can compose against this MVP without
breaking-change risk.

## R2. Add-request payload structure

The add-request is the simplest possible binding:

```
2 bytes    sender_identity_length (uint16 BE)
N bytes    sender_identity_bytes
1216       sender_public_bundle (HybridOnion.serialisePublicBundle)
```

Total: `1218 + sender_identity_length` bytes.

This binds alice's identity-string to her public bundle inside
the ciphertext. Bob's verification step compares the claimed
public bundle to the directory's binding — if they don't match,
the request is forged (someone other than alice constructed it).

Why include both fields? The identity-string alone is not enough
— bob needs to know alice's bundle to encrypt back to her in
the future (or to send an add-response). The bundle alone is
not enough — bob needs the identity-string to look it up in the
directory and confirm the binding.

## R3. Why we verify via the directory, not the ciphertext itself

A naïve verification would check "the ciphertext came encrypted
to bob, so the sender knew bob's bundle, so the sender is who
they claim". This is **wrong**: anyone can look up bob's bundle
in the public directory and construct an add-request impersonating
alice. The ciphertext only proves "the sender knew bob's bundle,"
which any directory consumer knows.

The correct verification is: "the directory binds the claimed
sender_identity to the claimed sender_public_bundle." This requires
the **PKG's MultiSignedEntry signature** to vouch for the binding
— which 015's `Directory` already verifies on every lookup. So
bob's verifyAddRequest is a directory lookup + a public-bundle
equality check.

This is SC-006: the trust decision MUST come from the directory,
not from anything the sender can shape.

## R4. Replay protection (or lack thereof in MVP)

A recorded add-request ciphertext is bit-replayable: bob can
re-decrypt the same bytes and get the same content. The MVP
does not include per-request nonces in the payload because:

1. **At the cryptographic layer**: replay is not a confidentiality
   problem. The ciphertext only carries alice's public info; a
   replay reveals nothing new.
2. **At the application layer**: bob's FriendStore catches
   duplicates — alice is already a friend, so re-adding is a
   no-op. The MVP signals this via `FriendStore.add` returning
   `false` rather than treating it as an error.
3. **Future hardening**: an "issued_at" timestamp + a sliding
   acceptance window would defend against very-stale replays.
   Deferred to a follow-up spec where it's needed.

## R5. Algorithm-ID assignment

Add-request ciphertexts use algorithm-ID `0x30`. Spec 015's
`IdentityEncryption` uses `0x20`. The PKG-discovery space is
allocated:

| ID    | Meaning                                              | Status |
|-------|------------------------------------------------------|--------|
| 0x30  | AddRequest_v1 (this spec)                            | CURRENT |
| 0x31  | Reserved for AddResponse_v1                          | RESERVED |
| 0x32  | Reserved for friendship-key dial-token registration  | RESERVED |
| 0x33–0x3F | Reserved for future friend-discovery variants   | RESERVED |

Separating from 015's space (0x20) and 013's space (0x10) lets
SDK / mixnet code dispatch on the alg-ID byte without ambiguity.

## R6. FriendStore semantics

The FriendStore is a local-only cache. It's NOT a privacy boundary
— anyone with access to bob's process memory can read it. The
real privacy property comes from the fact that lookups go through
the FriendStore instead of the PKG, so the PKG doesn't see them.

A future persistent backend (encrypted at rest) is a follow-up
spec. The MVP's in-memory store is sufficient for the
cryptographic-primitive demonstration.

API choices:

- `add(identity, bundle): Boolean` — returns `false` if the
  identity was already present (no error; idempotent re-add).
  Returns `true` if newly added.
- `lookup(identity): Option[HybridPublicBundle]` — pure read.
- `list(): Seq[Array[Byte]]` — enumeration of accepted
  friends; useful for UI listings.

The MVP doesn't expose `remove` — friendship-revocation is a
follow-up.

## R7. Failure-mode classification

| Failure | Returned as | Recoverable? |
|---|---|---|
| Wrong-length input bytes | `Left(InvalidLength)` | Programming bug — caller's responsibility |
| Unknown alg-ID | `Left(UnsupportedAlgorithm)` | Likely a different ciphertext type |
| Malformed inner payload | `Left(MalformedRequest)` | Sender bug or tampering |
| AEAD decrypt failed | `Left(DecryptionFailed)` | Tampered or addressed-to-someone-else |
| Identity not in directory | `Left(IdentityNotInDirectory)` | Snapshot stale; SDK may retry |
| Identity binding mismatch (forgery) | `Left(IdentityMismatch)` | Forgery attempt; SDK should NOT retry |

These mirror the patterns in 013 / 014 / 015 / 005: typed errors
for expected failure modes; throws only for programming bugs.

## R8. Reference: Alpenhorn's design vs Siida's adaptation

The original Alpenhorn paper used Boneh-Franklin IBE for the
sender→recipient encryption inside the add-request. Siida uses
HybridOnion (012) — PQ-hybrid ML-KEM-768 + x25519. The structure
is otherwise identical. The PQ migration upgrades the
cryptographic primitive without changing the protocol's privacy
properties.

One subtle change: in Alpenhorn, sender could encrypt to
recipient WITHOUT a directory lookup (BF-IBE's unilateral
property). In Siida, sender MUST first look up recipient's
bundle in the PKG directory — the same privacy regression 015's
threat-model documents. The same mitigation applies: route the
directory lookup through the mixnet to hide which identity the
sender is looking up.

## R9. What 019 does NOT cover

- **Mixnet routing** of add-requests: SDK (spec 007)
- **Cover-add-traffic** discipline: SDK
- **Add-response** flow: future spec
- **Friendship-key dial tokens**: future spec
- **Persistent FriendStore**: future spec
- **Friendship revocation**: future spec
- **Block-list / harassment defence**: future spec
- **Add-request batching across rounds**: SDK
- **Rate-limiting on the bob side** (e.g., "no more than N add-
  requests per round"): SDK or PKG-policy
