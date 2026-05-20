# Phase 0 Research: PQ Mixnet Onion Layer

**Feature**: [spec.md](./spec.md)
**Date**: 2026-05-20
**Status**: Complete — all FR-prefixed decisions resolved.

## R1. KEM choice — ML-KEM-768

**Decision**: ML-KEM-768 (NIST FIPS 203, formerly Kyber-768).

**Rationale**: BSI TR-02102-1's recommended PQ-KEM, with both
ANSSI and ENISA endorsing as the production-grade KEM. The 768
parameter set targets ~128-bit classical security equivalent; the
1024 variant targets ~192-bit and is overkill for general-purpose
onion-layer encryption. Public-key size 1184 bytes, ciphertext
size 1088 bytes — both significant overhead but well-studied.

Swedish provenance: lattice cryptanalysis work at Lund University
(Thomas Johansson, Patrik Ekdahl) reviewed the Kyber security
analysis pre-standardisation; not a direct design contribution
but a documented secondary-review lineage.

**Alternatives considered**:
- **ML-KEM-1024**: higher security margin but ~33% larger key
  material. Onion-layer overhead matters; the mixer's fixed cell
  has to fit it.
- **FrodoKEM**: BSI's "high assurance" recommendation for
  conservative deployments. Public-key ~10 KB — too large for
  per-message onion-layer overhead.
- **Classic McEliece**: long-term archival recommendation but
  ~261 KB public key — out of the question for per-message
  envelopes.
- **NTRU / Saber**: NIST Round 3 alternates, not standardised.

## R2. Classical half — x25519

**Decision**: x25519 ECDH (RFC 7748).

**Rationale**: Already in the Siida stack (NaCl `box` uses x25519
under the hood). Keeping x25519 minimises the delta the hybrid
introduces: same key shapes, same wire-format ECDH primitive,
just paired with ML-KEM. BSI TR-02102-1 keeps x25519 in its
recommended list for classical ECDH.

**Alternatives considered**:
- **Curve448**: higher classical security margin (224-bit vs
  128-bit). BSI recommends Curve448 for high-assurance
  deployments. Rejected because Siida's existing NaCl `box`
  ecosystem is built around x25519; switching the classical half
  is a separate decision worth its own spec. Future-proofing
  candidate.
- **secp256r1 (P-256)**: NIST-standard but slower, larger, and
  with seed-of-Dual_EC_DRBG-flavoured reputation issues. No
  benefit over x25519.

## R3. Combiner construction — SHA3-256

**Decision**:

```
shared_secret = SHA3-256(
  classical_ss (32 bytes) ||
  ml_kem_ss    (32 bytes) ||
  "siida/hybrid/v1/onion-layer" (28 bytes)
)
```

The combiner takes both raw 32-byte shared secrets plus a
domain-separation tag identifying the protocol layer.

**Rationale**: NIST SP 800-56C-r2 and ENISA's 2024 PQ hybrid
guidance both recommend a dual-input KDF construction where the
output security is `max(classical, PQ)` rather than `min`. A
hash-based combiner (SHA3-256 here) achieves that: an adversary
who breaks only one of the two halves cannot distinguish the
output from random. The 32-byte combined secret is the AEAD key
input directly.

**Alternatives considered**:
- **Concatenate-and-use-as-AEAD-key** (no hash): security degrades
  to `min(classical, PQ)`. Rejected outright.
- **HKDF-SHA-256 Extract-then-Expand**: more standard but extra
  complexity unnecessary for a fixed-output-length single use.
  The single SHA3-256 invocation is functionally HKDF-Extract
  with an empty salt.
- **BLAKE3**: faster but not as widely standardised; SHA3 is the
  BSI-recommended hash.

**Domain-separation tag rationale**: the tag prevents the same
KEM/ECDH share from being repurposed for a different protocol
layer (e.g., config-chain signing) and accidentally producing the
same AEAD key. The tag string is ASCII for auditability.

## R4. AEAD — ChaCha20-Poly1305

**Decision**: ChaCha20-Poly1305 (RFC 8439).

**Rationale**: IETF-standardised, widely audited, and the
modern-default symmetric AEAD. The NaCl `box` we're replacing uses
XSalsa20+Poly1305 (a sibling construction); the move to ChaCha20
is a small standardisation alignment, not a security regression.
BSI TR-02102-1 has ChaCha20-Poly1305 on its recommended-AEAD
list.

**Alternatives considered**:
- **XSalsa20+Poly1305** (the NaCl variant): functionally similar;
  smaller ecosystem support outside libsodium. Rejected.
- **AES-256-GCM**: ubiquitous but its nonce-misuse properties are
  worse than ChaCha20-Poly1305 for our use case (constant nonce
  on different keys is OK for either, but ChaCha20's failure mode
  is cleaner).
- **AES-256-GCM-SIV**: nonce-misuse resistant variant. Overkill
  for our deterministic-per-layer nonce derivation.

## R5. Nonce derivation

**Decision**: 12-byte AEAD nonce constructed as:

```
nonce[0..3]   = 0x00 0x00 0x00 0x00              (4-byte fixed prefix)
nonce[4..11]  = big-endian (layer_position : u64)
```

Where `layer_position` is the absolute layer index from the
client's perspective (layer 0 is the outermost, encrypted last).
For a three-hop chain that's 0, 1, 2 — three distinct nonces per
onion-build.

**Rationale**: Each layer uses a different key (different mixer's
hybrid bundle), so nonce reuse across keys is automatic. The
position-based derivation is deterministic for tests and avoids
RNG output in the nonce path. The fixed 0x00*4 prefix leaves
headroom for future format extensions without breaking the wire.

**Alternatives considered**:
- **Random nonce**: would require shipping the nonce alongside
  the ciphertext, increasing per-layer size by 12 bytes. Rejected.
- **HKDF-derive nonce from shared secret**: extra complexity for
  no security benefit when each key is fresh.

## R6. Wire format — versioned envelope

**Decision**: One onion-layer ciphertext is laid out as:

```
byte  0     : algorithm ID (0x01 for this spec)
bytes 1..32 : x25519 client public ephemeral (32 bytes)
bytes 33..1120: ML-KEM-768 ciphertext (1088 bytes)
bytes 1121..N : ChaCha20-Poly1305 ciphertext over (inner layer)
              | including a 16-byte trailing Poly1305 tag
```

Total fixed overhead per layer: 1 (alg) + 32 (x25519_eph) +
1088 (ml_kem_ct) + 16 (poly1305_tag) = **1137 bytes** of
per-layer envelope plus the inner payload size.

**Rationale**: All fields are positional; no length prefix
because the sizes are fixed by the algorithm. The leading
algorithm byte enables future PQ-only or scheme-bump variants
without a flag day (FR-003).

**Alternatives considered**:
- **CBOR / protobuf framing**: more parsing complexity, no
  security gain, ~5-10 bytes per layer of framing overhead.
- **Length-prefixed fields**: would allow heterogeneous ML-KEM
  variants per layer, but Siida pins the variant globally so
  length-prefix is wasted overhead.

## R7. Mixnet cell-size impact

**Constraint flagged for spec 004-mixnet-server**: per-layer
overhead grows from ~48 bytes (NaCl `box` MAC + nonce framing)
to 1137 bytes — a **+1089-byte per-layer** increase. For a
three-hop chain that's +3267 bytes of overhead per onion versus
the classical baseline. The mixnet's round-protocol cell-size
(in Vuvuzela's design, fixed per round to prevent length-based
linkage attacks) MUST accommodate this.

This is a coordination point with spec 004 when it lands. Two
options:
1. 004's fixed cell size accommodates the new overhead (likely
   simplest if cell sizes are already in the kilobytes range).
2. 004 picks a cell size that's tight for the classical case;
   012's hybrid layer requires the cell to grow, costing more
   per-round bandwidth across the network.

Recommendation to 004: choose a cell size of at least
`max(classical_overhead, hybrid_overhead) + max_inner_payload`,
with the hybrid case as the design driver. Documented expectation:
~4 KB cells (giving ~800 bytes of inner payload room after the
three-layer overhead).

## R8. Library choice — Bouncy Castle PQ provider

**Decision**: Bouncy Castle (BC) PQ provider for ML-KEM-768.
Pure-Java, MIT-licensed, audited; matches the JVM-native posture
of Principle V without introducing additional JNI surface.

**Rationale**: BC's ML-KEM implementation passed NIST's CAVP
validation and follows FIPS 203 verbatim. Pure-Java means no
per-arch native binaries — the kind of native-build matrix
complexity we have for gnark-crypto in 002 does not recur for
this primitive. Licence is MIT, compatible with our AGPL umbrella
under Principle III.

**Alternatives considered**:
- **liboqs via JNI**: would put us back in the per-arch native
  binary world (same shape as 002's gnark-crypto path). More
  performant than BC but the performance delta isn't load-bearing
  for our use case (we're at ~ms-per-encap, mixnet round budget
  is seconds).
- **Custom Scala / Kotlin implementation**: rejected by FR-011
  (audited library required).
- **AWS-LC**: NIST-validated but C-only; same JNI cost as liboqs.

## R9. Test vector strategy

**Decision**: KATs are derived from a fixed-seed harness using
the chosen Bouncy Castle implementation. Two committed JSON
files:

- `modules/crypto/test/resources/ml_kem_768_kat.json`: a single
  KAT entry derived from a fixed 32-byte seed, exposing the
  intermediate ML-KEM public key, ciphertext, and recovered
  shared secret. Used by `MlKem768Suite` for regression.
- `modules/crypto/test/resources/hybrid_onion_kat.json`: a single
  KAT entry for the full three-hop hybrid onion, fixed seed,
  exposing the wire-format bytes per layer and the recovered
  plaintext.

**Rationale**: Same self-referential KAT shape as 002. External
KATs against an independent BN254 / ML-KEM implementation are a
follow-up; the determinism + bilinearity + HNDL-resistance tests
catch regressions in the construction.

**Alternatives considered**:
- **NIST CAVS test vectors** for ML-KEM-768: available, but
  formatted for the NIST KAT response file format. Adapting them
  into JSON adds parsing surface; deferred to a follow-up that
  brings external KAT coverage.
- **IETF hybrid-handshake test vectors**: at draft stage as of
  2026-05-20; not stable enough to depend on yet.

## R10. Constant-time guarantees

**Decision**:

| Operation | Constant-time? | Source |
|---|---|---|
| ML-KEM-768 keygen, encap, decap | Yes | BC's reference impl is documented constant-time |
| x25519 ECDH | Yes | BC's curve25519 impl is constant-time |
| SHA3-256 combiner | Yes | All-byte; no data-dependent branches |
| ChaCha20-Poly1305 encrypt/decrypt | Yes | RFC 8439 reference construction |
| Wire-format parse / serialise | Acceptable | byte-by-byte memcpy; no secret-dependent branches |

The Scala layer (Siida-original code) MUST NOT branch on secret
inputs. Validation happens before any secret-touching code.

## R11. Public API surface

To be locked in `contracts/scala-api.md`:

```scala
package siida.crypto.api

object HybridOnion:
  opaque type HybridPublicBundle  // 32-byte x25519_pk + 1184-byte ml_kem_pk
  opaque type HybridSecretBundle  // 32-byte x25519_sk + 2400-byte ml_kem_sk
  opaque type OnionLayer          // wire-format bytes including alg ID
  
  def generateBundle(rng: SecureRandom): (HybridSecretBundle, HybridPublicBundle)
  
  def encrypt(
    recipient: HybridPublicBundle,
    payload:   Array[Byte],
    rng:       SecureRandom,
  ): OnionLayer
  
  def decrypt(
    secret: HybridSecretBundle,
    layer:  OnionLayer,
  ): Either[HybridOnionError, Array[Byte]]
  
  def serialiseLayer(layer: OnionLayer): Array[Byte]
  def deserialiseLayer(bytes: Array[Byte]): Either[HybridOnionError, OnionLayer]
  
  def serialisePublicBundle(b: HybridPublicBundle): Array[Byte]
  def deserialisePublicBundle(bytes: Array[Byte]): Either[HybridOnionError, HybridPublicBundle]
```

**Layer composition** (three-hop onion construction) lives in
the mixnet spec (004), not in 012. 012 provides only the
per-layer primitive. The caller composes layers by recursively
encrypting from innermost to outermost.

## R12. Open questions deferred to follow-ups

- **External KAT vectors**: same deferral pattern as 002.
- **PQ-only cutover timeline**: not in 012. Future spec.
- **Curve448 upgrade for the classical half**: future spec; not
  blocked by 012.
- **Onion-layer performance budget against round timing in
  spec 004**: real measurements happen when 004 lands.
- **Wire-format alg-ID space partitioning**: 0x00 (deprecated
  classical), 0x01 (this spec), 0x02+ (reserved). The actual
  meaning of 0x02 is whatever future spec defines it; this spec
  doesn't reserve specific values for known-future variants.
