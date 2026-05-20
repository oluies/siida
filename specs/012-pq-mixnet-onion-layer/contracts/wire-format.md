# Contract: Onion-Layer Wire Format

**Feature**: [spec.md](../spec.md) · [research R6](../research.md)

This document pins the on-wire byte layout of a single
`HybridOnion.OnionLayer` and the algorithm-ID space (FR-003).
Downstream specs (004-mixnet-server, 007-client-sdk) parse and
relay these bytes; any change to the layout requires a follow-up
spec amending this contract.

## Single-layer envelope (algorithm 0x01)

```
offset  size    field
─────── ─────── ────────────────────────────────────────────────────
0       1       algorithm ID (constant 0x01 for this spec)
1       32      x25519 ephemeral public key (sender's per-layer pk)
33      1088    ML-KEM-768 ciphertext (FIPS 203, parameter set 3)
1121    N       ChaCha20-Poly1305 ciphertext over the inner payload
1121+N  16      Poly1305 authentication tag (concatenated by AEAD spec)
```

**Total fixed overhead per layer**: 1 + 32 + 1088 + 16 = **1137 bytes**.

**Inner payload size**: N = `total_layer_bytes - 1153` (envelope
minus 16-byte tail tag minus 1137 fixed-overhead bytes; the AEAD's
output is ciphertext-and-tag concatenated, so the 16-byte tag is
implicit in the trailing 16 bytes).

The layer is positional — no length-prefixed fields, no framing
metadata. Recipients know the parse boundaries from the algorithm
ID alone.

## Algorithm-ID space

| ID    | Meaning                                              | Status |
|-------|------------------------------------------------------|--------|
| 0x00  | NaCl `box` (XSalsa20 + Poly1305 + x25519)            | DEPRECATED. Reserved so future 0x00 ciphertexts are recognised and explicitly rejected by 012-or-later mixers. NEW code MUST NOT emit 0x00. |
| 0x01  | Hybrid ML-KEM-768 + x25519, SHA3-256 combiner, ChaCha20-Poly1305 AEAD (this spec) | CURRENT. New onion layers emit this. |
| 0x02–0x7F | Reserved for future PQ-only or scheme-bump variants | RESERVED. Each follow-up spec picks a specific value. |
| 0x80–0xFF | Reserved for experimental / testing                | RESERVED. Never to appear in production traffic. |

**Refusal rule**: a mixer or recipient receiving a ciphertext whose
algorithm ID is not implemented MUST refuse with a uniform
`UnsupportedAlgorithm` error. The error MUST NOT reveal which IDs
ARE supported (FR-006).

## Combiner construction (alg 0x01)

After ML-KEM decapsulation and x25519 ECDH on the recipient side:

```
classical_ss = x25519(secret.x25519_sk, layer.x25519_eph_pk)   // 32 bytes
ml_kem_ss    = ml_kem_768_decap(secret.ml_kem_sk, layer.ml_kem_ct) // 32 bytes
aead_key     = SHA3-256(classical_ss || ml_kem_ss || "siida/hybrid/v1/onion-layer")
                                                                 // 32 bytes
```

The 28-byte ASCII tag `"siida/hybrid/v1/onion-layer"` is appended
literally; no NUL terminator, no length prefix. Total combiner
input is 32 + 32 + 28 = 92 bytes.

## AEAD construction (alg 0x01)

ChaCha20-Poly1305 per RFC 8439:

- Key: 32-byte `aead_key` from the combiner above
- Nonce (12 bytes): `0x00 0x00 0x00 0x00 || big-endian u64 layer_position`
  - `layer_position` is the absolute index from the client's
    perspective (outermost = 0, innermost = `hop_count - 1`)
- Associated data: empty
- Plaintext: the inner payload bytes (next layer's full envelope
  for non-final hops; the actual user-message ciphertext for the
  final hop)

The 16-byte Poly1305 tag is the trailing 16 bytes of the layer's
on-wire ciphertext slice.

## Hybrid public bundle wire format

Used by 005-pkg-keybootstrap to distribute recipient public keys.

```
offset  size    field
─────── ─────── ─────────────────────────────────
0       32      x25519_pk
32      1184    ml_kem_pk (FIPS 203 encoded)
```

**Total**: 1216 bytes.

## Hybrid secret bundle wire format

PKG-internal only. Never crosses the network. Stored encrypted at
rest by the SDK in trusted client storage.

```
offset  size    field
─────── ─────── ─────────────────────────────────
0       32      x25519_sk
32      2400    ml_kem_sk (FIPS 203 encoded)
```

**Total**: 2432 bytes.

## Forward-compatibility invariant

If a recipient receives an algorithm-ID byte the deserialiser
recognises (0x01) but the rest of the envelope is shorter than
expected, deserialisation MUST reject with `InvalidLength`. There
is no auto-resync, no partial parse. The wire format is
fixed-size per algorithm; new fixed sizes mean new algorithm IDs.
