# Phase 0 Research: Post-Quantum Roadmap

**Feature**: [spec.md](./spec.md)
**Date**: 2026-05-19
**Status**: Roadmap research — captures the per-primitive analysis the
spec's user stories commit to.

## R1. Threat-model rationale

The current constitution v1.0.0 names "a global passive adversary
observing every link, plus active compromise of a strict minority
of mixers" (Security & Threat Model section). Quantum capability is
silent. That silence is read by current implementation specs as
*classical-only adversaries*, which is why 002 was allowed to ship
pairing-based crypto.

**Harvest-now-decrypt-later (HNDL) is the immediate concern.** Any
adversary collecting Siida ciphertext today can, on the arrival of
a sufficiently large quantum computer (estimates range from a
decade to never; the conservative posture treats "decade" as
plausible enough to act on), retroactively:

- Compute the PKG master secret from the master public key
  (g1^s ∈ G1; recover s via Shor's algorithm)
- Decrypt every IBE message ever encrypted under that master key
- Forge BLS signatures by computing private keys from public keys
- Decrypt every NaCl `box` onion layer by breaking x25519 ECDH

Siida's metadata-privacy goal (Constitution Principle I) is
specifically about persistent secrecy. HNDL violates that goal
**without any quantum capability deployed today** — the attacker
just needs storage.

Decision: the constitution v2.0.0 amendment explicitly adds
quantum adversaries with HNDL capability to Principle I, applying
to all data crossing the network from the amendment's
ratification-date forward.

## R2. European certification landscape

| Agency | Scope | Current PQ posture (2026-05-19) |
|---|---|---|
| BSI (DE) | National crypto guidance, BSI TR-02102-1 | Recommends ML-KEM, ML-DSA; FrodoKEM for high assurance; Classic McEliece for archival |
| ANSSI (FR) | National crypto guidance | Conservative; recommends hybrid mode for production; tracks BSI for primary choices |
| ENISA (EU) | EU-level cyber agency | Tracks both BSI and ANSSI; publishes PQ readiness reports |
| FRA (SE) | Swedish Defense Radio Establishment | Internal use; public guidance limited; defers to ENISA in civilian contexts |
| RISE (SE) | Research institutes; non-regulatory | Active in PQ research; collaborates with KTH and Lund |

**Practical implication**: "European-certified" in 2026 effectively
means *BSI-endorsed*, with ANSSI and ENISA agreeing. Sweden does not
operate a national crypto certification scheme separate from the
above. Preference for Swedish work therefore expresses through
research provenance, not certification.

## R3. Swedish-affiliated PQ research provenance

The following PQ-related research has documented Swedish institutional
involvement; used in the per-primitive table below as a tie-breaker.

| Researcher / Group | Institution | PQ relevance |
|---|---|---|
| Thomas Johansson | Lund University | LWE cryptanalysis, McEliece variants, code-based PQC |
| Patrik Ekdahl | Lund University | Symmetric cryptanalysis (PQ-relevant for KEM combiners) |
| KTH crypto group | KTH Stockholm | Lattice-based crypto, ZK proofs |
| Daniel Augot (visiting) | Lund (visiting) | Code-based crypto |
| RISE Cybersecurity | RISE | PQ migration tooling |

No PQ scheme listed below is exclusively Swedish in design, but
several have substantial Swedish-cryptanalyst review (notably
Classic McEliece, which has been studied at Lund extensively).

## R4. Per-primitive replacement table

| # | Siida primitive (current) | Used by | What quantum breaks | PQ replacement | European cert anchor | Swedish provenance | Migration phase | Spec slot |
|---|---|---|---|---|---|---|---|---|
| 1 | NaCl `box` (x25519+XSalsa20+Poly1305) for mixnet onion layers | mixnet (004), client SDK (007) | x25519 ECDH (Shor) | **Hybrid ML-KEM-768 + x25519**; combiner = SHA3-256 hash of both shared secrets | BSI TR-02102-1 recommends ML-KEM | Lund cryptanalysis of lattice schemes | Hybrid first; PQ-only after 5-year confidence window | 012-pq-mixnet-onion-layer |
| 2 | BLS signature on G2 (Vuvuzela layout) | config-chain (006), mixer attestations (004) | Co-CDH on BN254 (Shor) | **ML-DSA-65** (FIPS 204) for single sigs; lose aggregation. Alternative: SLH-DSA (hash-based, stateless, larger) for archival signatures | BSI TR-02102-1 to add ML-DSA; ANSSI accepts | Some cryptanalytic review at Lund | PQ-only cutover; no hybrid (sig schemes don't combine usefully) | 013-pq-bls-replacement |
| 3 | BLS aggregate signature (sum in G2) | config-chain (006) (planned) | Same as #2; aggregation also lost | **No PQ aggregate signature** is production-grade. Substitute: batch verification of individual ML-DSA signatures, OR multi-signature SQIsign variant (research) | None yet | None | Accept loss of aggregation OR redesign config-chain to not require aggregation | 014-pq-config-chain-redesign |
| 4 | Boneh-Franklin IBE on BN254 | PKG (005), client SDK (007) | BDH on BN254 (Shor) | **No production-grade PQ-IBE**. Substitute: replace IBE with PKG-issued ML-KEM keys looked up by identity (the PKG becomes a directory rather than a key derivation function) | Building blocks (ML-KEM) are BSI-endorsed; the construction is novel | RISE has worked on directory-based identity systems | Protocol redesign, not drop-in swap. Major scope. | 015-pq-identity-encryption |
| 5 | Hash-to-curve (SSWU on BN254) | IBE identity hash, BLS message hash, PoP hash | Underlying curve broken (Shor); hash construction itself fine | N/A — only relevant after the underlying curve changes | — | — | Disappears with primitives 1, 2, 4 | folded into 012-015 |
| 6 | SHA-256 (KDF, identity tag, generally) | IBE KDF, identity tags, generic hashing | Grover quadratic speedup; 256→128 bit effective security | **SHA3-256** or stay on SHA-256 with longer outputs (SHA-512) | BSI TR-02102-1: both fine | KTH symmetric-crypto group | No urgent migration; Grover speedup leaves SHA-256 at ~128-bit PQ security which is "acceptable" by BSI | None — keep current |
| 7 | Scalar randomness (SecureRandom seeded from OS) | All primitives | No quantum advantage | Same | — | — | — | None |

**Long-term archival path** (separate consideration): Classic
McEliece for KEM, SLH-DSA (SPHINCS+) for signatures. Both are
extensively studied at Lund. Pre-empt this as a future spec for
config-chain signatures that need to remain verifiable decades from
now.

## R5. Hybrid handshake combiner

For every hybrid (PQ + classical) primitive, the combined shared
secret MUST be derived by a hash-based combiner over both
constituent secrets with a domain-separation tag:

```
shared_secret = SHA3-256(
  classical_ss || ML_KEM_ss ||
  "siida/hybrid/v1/" || primitive_id || epoch_id
)
```

This construction has security `max(classical, PQ)` against an
adversary that breaks only one of the two (as opposed to `min` for
naive concatenation). Reference: NIST SP 800-56C-r2 and ENISA's
2024 hybrid-PQC guidance.

## R6. Spec slots reserved by this roadmap

| Slot | Title | Scope |
|---|---|---|
| 012 | pq-mixnet-onion-layer | Replace NaCl `box` with hybrid ML-KEM + x25519 for the round-aligned onion layers |
| 013 | pq-bls-replacement | Replace single BLS signatures with ML-DSA; drop aggregation interface |
| 014 | pq-config-chain-redesign | Redesign config-chain to not require aggregate signatures (or batch them via ML-DSA batch verify) |
| 015 | pq-identity-encryption | Replace Boneh-Franklin IBE with a PKG-directory + ML-KEM scheme; protocol-level change |

The existing sketched roadmap slots get bumped:

- old 010-chat-client stays 010 (unaffected; PQ pushes into 012+)
- old 011-observability becomes 016 (after PQ specs)

This means the README roadmap table needs five new rows and one
moved row.

## R7. What this spec does NOT decide

- **Which exact ML-KEM / ML-DSA parameter set** (768 vs 1024,
  etc.) for each per-primitive replacement. That's per-spec.
- **The wire-format versioning byte position**. That's per-spec at
  the cryptographic-envelope level (per-message in mixnet, per-
  signature in config-chain).
- **Timing of PQ-only cutover**. That's per-spec based on real-
  world deployment confidence.
- **Whether to maintain a Mill build dependency on Bouncy Castle
  Java PQ providers, or to write JNA wrappers around a C
  implementation, or to use pure-Java lattice crypto**. Each
  per-primitive spec picks.
- **Whether to keep BN254 at all** post-migration. Probably yes for
  the duration of any hybrid period; possibly no afterwards.

## R8. Open questions deferred to per-primitive specs

- Performance budgets for hybrid handshakes (ML-KEM-768 is ~1KB
  pubkey + ~1KB ciphertext per encapsulation; significant for
  metadata-overhead-sensitive mixnet rounds)
- Whether the PKG-directory model in primitive #4's replacement
  preserves all the privacy properties the IBE construction
  provided
- Whether config-chain can tolerate loss of aggregate signatures
  by switching to batch verification (significant for verifier
  cost during PKG rotation)
- Long-term archival signature choice (SLH-DSA-SHA2-128f vs other
  hash-based options)
