# Contract: Public Scala API of `siida.crypto.api.PqSignature`

**Feature**: [spec.md](../spec.md) · **Stability gate**: FR-010

```scala
package siida.crypto.api

import java.security.SecureRandom

object PqSignature:

  opaque type PqPrivateKey = ...   // 4032 bytes (ML-DSA-65 sk + 1-byte alg ID)
  opaque type PqPublicKey  = ...   // 1953 bytes (ML-DSA-65 pk + 1-byte alg ID)
  opaque type Signature    = ...   // 3310 bytes (ML-DSA-65 sig + 1-byte alg ID)

  // ── Keygen ──────────────────────────────────────────────

  def generateKeyPair(rng: SecureRandom): (PqPrivateKey, PqPublicKey)
  def publicKey(sk: PqPrivateKey): PqPublicKey

  // ── Sign / verify ──────────────────────────────────────

  def sign(sk: PqPrivateKey, message: Array[Byte]): Signature

  /** Verify one signature. Returns false on any failure mode
   *  (wrong key, tampered message, malformed bytes, unsupported
   *  algorithm ID). Does NOT throw on per-call failures.
   */
  def verify(pk: PqPublicKey, message: Array[Byte], sig: Signature): Boolean

  /** Verify many signatures in a single batched operation.
   *  Returns true iff every tuple verifies. Uses the Scala-layer
   *  randomised-coefficient construction (research R3); CPU cost
   *  is ~0.6n verifications for n ∈ [8, 32].
   *
   *  Empty input returns false (the empty product is trivially
   *  true but the caller almost certainly meant something else).
   *  No information leaks about WHICH tuple failed on rejection.
   */
  def batchVerify(tuples: Seq[(PqPublicKey, Array[Byte], Signature)]): Boolean

  // ── Serialisation ─────────────────────────────────────

  def serialisePrivateKey(sk: PqPrivateKey): Array[Byte]
  def deserialisePrivateKey(bytes: Array[Byte]): Either[PqSignatureError, PqPrivateKey]

  def serialisePublicKey(pk: PqPublicKey): Array[Byte]
  def deserialisePublicKey(bytes: Array[Byte]): Either[PqSignatureError, PqPublicKey]

  def serialiseSignature(sig: Signature): Array[Byte]
  def deserialiseSignature(bytes: Array[Byte]): Either[PqSignatureError, Signature]

  // ── Constants ────────────────────────────────────────

  object AlgorithmID:
    val MlDsa65: Byte = 0x10
    // 0x11 reserved for ML-DSA-87, 0x12 SLH-DSA, 0x13 Falcon
```

Add to `siida.crypto.api.Errors`:

```scala
enum PqSignatureError derives CanEqual:
  case UnsupportedAlgorithm
  case InvalidLength
  case MalformedKey
  case MalformedSignature
```

## Wire formats

| Type | Size | Layout |
|---|---|---|
| `PqPrivateKey` | 4033 bytes | 1-byte alg ID (`0x10`) + 4032-byte ML-DSA-65 sk |
| `PqPublicKey`  | 1953 bytes | 1-byte alg ID (`0x10`) + 1952-byte ML-DSA-65 pk |
| `Signature`    | 3310 bytes | 1-byte alg ID (`0x10`) + 3309-byte ML-DSA-65 sig |

> **Source-of-truth note**: FIPS 204 Table 1 gives the ML-DSA-65
> signature as 3309 bytes (the figures 3293/3294 in earlier drafts
> were a documentation error). The implementation in
> `PqSignature.scala` exports `SignatureBytes = 3309` and the wire
> envelope is therefore 3310 bytes.

Each carries the algorithm ID so a future cutover to ML-DSA-87 or
SLH-DSA is detectable per-message.

## What's NOT here

- **`aggregate`** — no equivalent. Per 011 R2: PQ aggregate
  signatures are research-stage; 013 doesn't ship one.
- **`proofOfPossession`** — the classical BLS PoP was a rogue-key
  defence for aggregation. Without aggregation it's unnecessary.
  If a future spec needs a PoP-like primitive for a non-aggregation
  reason, it adds it then.
- **Hybrid classical + PQ signatures** — explicitly rejected in
  research R4.

## Stability and compatibility

Per FR-010: once 013 merges, no signature in this file changes
without a follow-up spec. The classical `siida.crypto.api.BLS` API
remains in service (with `@deprecated` annotation) until every
consumer migrates; removal is a future spec.
