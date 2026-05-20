# Phase 0 Research: PQ Identity Encryption

**Feature**: [spec.md](./spec.md)
**Date**: 2026-05-20
**Status**: Complete

## R1. Why no PQ-IBE drop-in

Boneh-Franklin IBE relies on the Bilinear Diffie-Hellman assumption
on a pairing-friendly curve (BN254 in Siida's case). Shor's
algorithm breaks the underlying ECDLP, so the entire IBE
construction is quantum-vulnerable.

Replacement candidates (none production-ready as of 2026-05):

| Scheme | Family | Status | Why not |
|---|---|---|---|
| GGH-based IBE | Lattice | Research | No production library; standardisation status uncertain |
| Agrawal-Boneh-Boyen IBE | Lattice (LWE) | Research | No NIST/BSI candidate; large keys (>10 KB) |
| Code-based IBE | Code | Theoretical | No concrete scheme; not in any standardisation process |
| Isogeny IBE | Isogeny | Theoretical post-SIDH | SIDH broken in 2022; SIKE withdrawn |

Per 011 R1: the production-ready alternative is a **protocol
redesign** — PKG-directory + HybridOnion — that delivers
identity-addressed encryption with PQ security at the cost of
sender→PKG observability.

## R2. Threat-model delta vs Boneh-Franklin IBE

**Boneh-Franklin IBE (spec 002, classical):**

| Adversary | Sees |
|---|---|
| Global passive adversary | Wire bytes (encrypted) |
| Compromised mixer | Onion layer (can't decrypt; classical NaCl box) |
| The PKG | Identity → key issuances; NOT per-encryption events |

**PKG-Directory + HybridOnion (this spec, PQ):**

| Adversary | Sees |
|---|---|
| Global passive adversary | Wire bytes (encrypted PQ-safely via HybridOnion) |
| Compromised mixer | Onion layer (can't decrypt) |
| The PKG | Identity → bundle publications AND **per-lookup events** if queries are not anonymized |
| Quantum-capable adversary harvesting today's traffic | Cannot decrypt later (HybridOnion is HNDL-resistant) |

The new line in the third row is the cost. The PKG was a
key-issuance authority before; now it's also a lookup directory.
A compromised or curious PKG can build a "who looked up whom"
graph.

**Mitigation**: route directory queries through the mixnet (the
PKG is just another recipient on the network from the SDK's
perspective). This makes "lookup-of-Y by sender X" indistinguishable
from "lookup-of-Y by sender Z" at the wire level. The PKG still
sees query-content (the identity being looked up) — but cannot
attribute the query to a specific sender.

**Residual leak**: query timing (the PKG knows when lookups
happen) and query volume (the PKG knows how many lookups in
aggregate). Cover traffic at the SDK's directory-lookup layer
mitigates timing; volume-based attacks remain.

## R3. Why not pre-fetch all directory entries

An alternative to anonymous lookup is: every SDK client downloads
the FULL directory periodically, so individual lookups never
touch the PKG. Bandwidth tradeoff:

- 1 million identities × 1216 bytes per bundle = 1.2 GB
- Plus N bytes of signature per entry from MultiSignedEntry
  (~26 KB per 8-signer entry, see 014 wire-format) = ~26 GB
  if every entry is independently signed

Even with compression and incremental updates (only new/changed
entries downloaded), the bandwidth is excessive for casual
clients. Reserve as a deployment option for high-assurance
clients (those who can't tolerate the per-query metadata leak);
default is anonymous-routed per-query lookup.

## R4. Wire format for an IdentityCiphertext

**Decision**: thin wrapper over HybridOnion's wire format.

```
offset  size       field
0       1          algorithm ID (0x20 for this spec)
1       N          HybridOnion.OnionLayer wire bytes (1137 + payload)
```

Total: `1 + 1137 + |payload| = 1138 + |payload|` bytes.

**Rationale**: the actual cryptography lives in
`HybridOnion.encrypt`; 015 contributes a thin envelope marker so
the SDK / mixnet can distinguish "identity-addressed message" from
other onion-layered traffic.

**Algorithm-ID space**: 0x20 reserved for this spec; 0x21+ for
future identity-encryption variants. (Distinct from 012's
onion-layer IDs 0x00-0x0F and 013's signature IDs 0x10-0x1F.)

## R5. Directory data structure

**Decision**: opaque to 015. The `Directory` Scala type wraps:

```
identity_bytes → (HybridPublicBundle, MultiSignedEntry attesting the binding)
```

Plus the roster of public keys against which the MultiSignedEntry
verifies.

Spec 005 (PKG) defines the persistent storage format, the
network-fetch protocol, and the caching strategy. 015 only
exposes the in-memory API.

**API shape**:

```scala
trait Directory:
  /** Look up an identity. Returns the bundle and the verified
   *  signature, or an error.
   */
  def lookup(identity: Array[Byte]): Either[IdentityEncError, HybridOnion.HybridPublicBundle]
```

Implementations are 005's concern. Tests in 015 use an in-memory
mock.

## R6. SignedDirectory verification flow

Per FR-005, every directory entry the sender uses MUST carry a
valid `MultiSignedEntry` signature from the current PKG roster.
The verification chain:

```
1. Sender holds the current PKG roster (Seq[PqPublicKey])
2. SDK loads directory entry for identity X
3. Entry contains: (HybridPublicBundle, MultiSignedEntry over the
   binding identity_bytes ++ bundle_bytes ++ epoch)
4. Sender calls MultiSignedEntry.verify(roster, threshold,
   "siida/pkg-directory/v1" tag, entry)
5. If Valid → use the bundle
6. Otherwise → InvalidDirectorySignature
```

The roster itself is obtained from the config chain (006). 015
relies on 006 having shipped a current roster snapshot — the SDK
keeps both the roster and the directory in sync via spec 007's
cache.

## R7. HybridOnion's algorithm-ID byte vs IdentityCiphertext's

The OnionLayer inside an IdentityCiphertext has its own algorithm
ID (`0x01` from 012). The IdentityCiphertext envelope prefixes
another algorithm ID (`0x20`). The two are in DIFFERENT spaces
because they identify different things:

- 012's `0x01` identifies the cryptographic construction of the
  hybrid handshake
- 015's `0x20` identifies the outer protocol layer

A mixnet relay sees `0x20` and knows "this is an identity-
addressed message, route normally"; a recipient inside their SDK
peels off `0x20` and feeds the inner bytes to `HybridOnion.decrypt`.

## R8. Privacy mitigations summary

| Mitigation | Cost | Effectiveness |
|---|---|---|
| Anonymous-routed lookup (default) | SDK round-trip via mixnet | High — PKG can't attribute query to sender |
| Pre-fetch full directory | Bandwidth (GB-scale) | Total — PKG never sees per-query lookups |
| Bloom-filter prefetch | Bandwidth (MB-scale), false-positive rate | Partial — PKG sees lookups that bypass cache |
| Padded query rate | Cover traffic | Mitigates query-timing inference |
| Query rate caps | DOS resistance | Side effect: smooths query rate |

Spec 005 picks the default mitigation set; 015 mandates that the
anonymous-routed option be available.

## R9. Test vector strategy

Same self-referential KAT shape as 002/012/013/014. One committed
JSON file:

```
specs/015-pq-identity-encryption/test/resources/identity_enc_kat.json
```

Contents: a (sender_seed, recipient_bundle_seed, identity_string,
message, expected_ciphertext_bytes) tuple. Generated via a fixed-
seed harness using the in-tree HybridOnion. External KAT vectors
deferred.

## R10. Open questions deferred to follow-ups

- **External KAT vectors** against an independent
  ML-KEM-768 implementation (NIST CAVS adapted): follow-up.
- **PQ-IBE if/when standardised**: future spec.
- **Bloom-filter prefetch protocol** for SDK-side cache miss
  detection: spec 007's concern.
- **PKG-side query-rate caps and cover traffic**: spec 005's
  concern.
- **Threshold encryption** (multiple PKGs collaboratively
  issuing bundles, avoiding a single PKG-compromise vector):
  research-stage; future spec.
