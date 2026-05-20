# Phase 0 Research: PKG Key-Bootstrap

**Feature**: [spec.md](./spec.md)
**Date**: 2026-05-20
**Status**: Complete

## R1. Alpenhorn's PKG model

Alpenhorn (Lazar & Zeldovich, OSDI 2016) introduced the
PKG-friend-discovery design that Siida is downstream of. Two
moving parts:

1. **PKG issuance**: a user registers an identity with the PKG;
   the PKG issues a Boneh-Franklin IBE secret bundle. This is
   what 005's MVP does (replacing BF-IBE with HybridOnion per
   spec 015's redesign).
2. **Friend discovery**: a sub-protocol where alice asks the
   PKG to introduce her to bob, and bob (later) accepts. This
   uses the mixnet itself to hide who's discovering whom. **Out
   of scope for 005's MVP** — separate spec.

Both halves use the mixnet for transport in production. 005's
MVP is purely the issuance + directory primitive; no network.

## R2. Signed-binding payload (FR-006)

The PKG signs over a structured payload that ties the identity
string to the public bundle and the allocated mailbox-id:

```
offset      size                  field
0           2                     identity_length (uint16 BE)
2           identity_length       identity_bytes
2 + IL      8                     mailbox_id (uint64 BE)
10 + IL     1216                  public_bundle_wire_bytes (012 spec)
```

Total: `1226 + identity_length` bytes.

The 1216-byte size is fixed by spec 012's
`HybridPublicBundle` wire format. The identity-length prefix
lets the directory consumer parse the payload deterministically.

Spec 015's `Directory.inMemory` reads this payload, extracts
the `public_bundle_wire_bytes`, and uses the surrounding
`MultiSignedEntry.verify` to confirm the PKG roster's signature.

## R3. Mailbox-id allocation

The MVP uses a simple monotonic counter starting at 1. The PKG
constructor takes an `initialMailboxId: Long` parameter so tests
can verify reserved-id-skip behaviour deterministically.

Reserved values to skip:
- `0L` (CoverMailboxId per spec 004)
- `-1L` (BroadcastMailboxId per spec 004)

In production, a future spec may switch to a hash-based
allocator (so mailbox-id reveals nothing about issuance order)
or a randomised one. The MVP's sequential counter is simple,
testable, and gives every identity a stable mailbox-id for the
lifetime of the PKG.

## R4. Threshold signer selection

Spec 014's `MultiSignedEntry.assemble` takes
`Seq[(signer_index, signature)]`. The PKG needs to pick which
signers contribute. MVP: signers `[0, threshold)` — the first M
of N. Rationale:

- Simplest possible policy
- Deterministic (FR-009 — same PKG + same identity → same entry)
- Production-acceptable: the threshold is M-of-N; if any of the
  first M fails (key compromise, key lost), a follow-up spec
  adds policy-driven selection

A future spec may add policies like "rotating signers per epoch"
or "load-balanced across roster". 005's MVP doesn't try to
optimize this.

## R5. Why the PKG doesn't retain the secret bundle

The PKG generates a fresh `HybridSecretBundle` per identity and
returns it to the caller. After return, the PKG keeps:
- The PUBLIC bundle (in the directory entry payload)
- The `MultiSignedEntry` proof
- The mailbox-id

It does NOT keep the secret bundle. The user is responsible for
holding their own secret bundle and presenting it on incoming
ciphertext decryption.

This is the right shape: the PKG's compromise should not reveal
all users' messages. A compromised PKG can forge new identities,
suppress lookups, or publish wrong bundles — but it cannot
decrypt past traffic.

The MVP enforces this by construction: `Pkg.issueIdentity`
generates the secret, packs the public into the directory entry,
returns the secret, and lets it go.

## R6. Determinism (FR-009)

`Pkg.create` + a sequence of `issueIdentity` calls with
fixed-seed RNGs MUST produce byte-identical state. This is the
testability hinge that makes the MVP verifiable.

Sources of non-determinism to control:
- `HybridOnion.generateBundle(rng)` — seeded RNG controls this
- `PqSignature.sign(sk, msg)` — deterministic by spec 013
  design (FIPS 204 rnd=0^32 path)
- `MultiSignedEntry.assemble` — pure function over inputs
- Mailbox-id allocation — sequential counter
- Identity storage — Map with bytes-keyed entries; iteration
  order can vary, so all snapshot/lookup code uses explicit
  sorting where order matters

In practice the MVP achieves determinism cleanly: fixed-seed
RNG in tests → fixed signed bundles, fixed signatures, fixed
mailbox-ids.

## R7. What happens on `PkgError` paths

The PKG returns errors as `Either[PkgError, _]` for expected
failure modes:
- `EmptyRoster` (config error)
- `InvalidThreshold` (threshold > roster size)
- `IdentityAlreadyExists` (duplicate)
- `MailboxIdExhausted` (theoretical; 2^63 IDs)

Programming errors (wrong-length keys crossing API boundaries,
crypto-layer panics) still throw, same convention as the rest of
the codebase.

## R8. Reference: Vuvuzela's PKG

Vuvuzela's original PKG was Boneh-Franklin IBE-based — it held
the master secret and issued per-identity private keys
deterministically. Siida's PKG (spec 015's redesign) instead
generates **fresh per-identity bundles** via `HybridOnion`, so
the PKG no longer holds a single master-secret-that-rules-them-
all. Compromise blast radius:

| Property | Vuvuzela PKG | Siida PKG (005) |
|---|---|---|
| Master secret | Single BF master key | None — per-identity bundles |
| Compromise impact | Decrypt all past + future identity traffic | Forge new identities + suppress lookups; cannot decrypt past traffic |
| Recovery | Re-issue master + all bundles | Reissue per-compromised identity |
| Forward secrecy across compromises | No | Yes (per-identity bundles independent) |

This is a real improvement bought by the PQ migration. Documented
in spec 015's threat-model.md.

## R9. What 005 does NOT cover (re-affirmed)

- Friend discovery sub-protocol — separate spec
- Persistent storage — separate spec
- Network transport (issuance API over the wire) — separate spec
- Sybil resistance / proof-of-ownership policy — separate spec
- Live roster rotation via config chain — spec 006 integration
- Bloom-filter / partial directory fetch — separate spec when
  the directory size becomes an operational concern
- PKG operator tooling (key gen, audit logs, metrics) — separate
  spec
