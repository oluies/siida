# Contract: Public Scala API of `siida.crypto.api.HybridOnion`

**Feature**: [spec.md](../spec.md) · **Stability gate**: FR-010
(no rename or signature change after 012 merges without a follow-up
spec)

Downstream consumers — 004 mixnet-server, 005 pkg-keybootstrap,
007 client-sdk — lock onto this surface.

```scala
package siida.crypto.api

import java.security.SecureRandom

object HybridOnion:

  // ── Opaque types ──────────────────────────────────────────────

  /** Recipient's distributable hybrid public bundle.
   *  Wire format: 32-byte x25519_pk ++ 1184-byte ml_kem_pk.
   *  Total: 1216 bytes.
   */
  opaque type HybridPublicBundle = ...

  /** Recipient's secret material. Must NEVER cross a process boundary
   *  in serialised form except into trusted PKG / SDK storage.
   *  Wire format (PKG-internal): 32-byte x25519_sk ++ 2400-byte ml_kem_sk.
   *  Total: 2432 bytes.
   */
  opaque type HybridSecretBundle = ...

  /** A single onion-layer ciphertext envelope.
   *  Wire format: see contracts/wire-format.md.
   *  Carries algorithm ID, ephemeral x25519 pk, ML-KEM ciphertext,
   *  ChaCha20-Poly1305 ciphertext-and-tag of the inner payload.
   */
  opaque type OnionLayer = ...

  // ── Keypair generation ────────────────────────────────────────

  /** Generate a fresh hybrid bundle pair. RNG MUST be
   *  cryptographically strong in production.
   */
  def generateBundle(rng: SecureRandom): (HybridSecretBundle, HybridPublicBundle)

  /** Project just the public half of a secret bundle. */
  def publicBundle(secret: HybridSecretBundle): HybridPublicBundle

  // ── Encrypt / Decrypt ─────────────────────────────────────────

  /** Encrypt a single payload to a recipient's hybrid bundle.
   *  Refuses if the bundle is incomplete (FR-005). RNG must be
   *  cryptographically strong; tests pass a deterministic stream.
   */
  def encrypt(
    recipient: HybridPublicBundle,
    payload:   Array[Byte],
    rng:       SecureRandom,
  ): OnionLayer

  /** Recover the payload using the recipient's secret bundle. */
  def decrypt(
    secret: HybridSecretBundle,
    layer:  OnionLayer,
  ): Either[HybridOnionError, Array[Byte]]

  // ── Serialisation ─────────────────────────────────────────────

  def serialiseLayer(layer: OnionLayer): Array[Byte]

  /** Validates the algorithm ID byte (FR-006) and the on-wire
   *  byte sizes; subgroup-checks the embedded x25519 ephemeral.
   *  Does NOT decapsulate — that happens in `decrypt`.
   */
  def deserialiseLayer(bytes: Array[Byte]): Either[HybridOnionError, OnionLayer]

  def serialisePublicBundle(b: HybridPublicBundle): Array[Byte]
  def deserialisePublicBundle(bytes: Array[Byte]): Either[HybridOnionError, HybridPublicBundle]

  def serialiseSecretBundle(b: HybridSecretBundle): Array[Byte]
  def deserialiseSecretBundle(bytes: Array[Byte]): Either[HybridOnionError, HybridSecretBundle]

  // ── Constants ────────────────────────────────────────────────

  /** Algorithm IDs reserved in the wire format. */
  object AlgorithmID:
    val DeprecatedClassical: Byte = 0x00
    val Hybrid_MlKem768_x25519_v1: Byte = 0x01
    // 0x02+ reserved for future PQ-only or scheme-bump variants
```

Add to `siida.crypto.api.Errors`:

```scala
enum HybridOnionError derives CanEqual:
  case IncompleteBundle
  case UnsupportedAlgorithm
  case InvalidPoint
  case InvalidLength
  case DecapsulationFailed   // either KEM or AEAD failed; uniform
  case MalformedCiphertext(reason: String)
```

## Contract guarantees

1. **Stability** (FR-010): no symbol above changes between 012's
   merge and an explicit follow-up spec.
2. **Quantum-safety** (FR-001, Constitution v2.0.0 Principle I): a
   quantum-capable adversary that knows only the classical x25519
   share — having either broken ECDLP or harvested the ephemeral
   privately — cannot decrypt the layer. The ML-KEM share is the
   second pillar.
3. **No classical fallback** (FR-005): an incomplete bundle yields
   `Left(IncompleteBundle)`, never a silent downgrade to
   classical-only NaCl `box`.
4. **Uniform decapsulation errors** (FR-006): callers cannot
   distinguish "KEM decap failed" from "AEAD tag failed" by
   inspecting the error tag — both are `DecapsulationFailed`. This
   prevents side-channel inference about which half of the hybrid
   broke.
5. **Determinism** (FR-007): for fixed-seed RNG, every operation
   produces bit-identical output across Linux/amd64, Linux/arm64,
   and Darwin/arm64.
