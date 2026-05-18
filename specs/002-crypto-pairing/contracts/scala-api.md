# Contract: Public Scala API of `modules/crypto`

**Feature**: [spec.md](../spec.md)

This is the contract downstream modules (`pkg` for 004, `configchain`
for 005, `sdk` for 006, `agent` for 007) will lock onto per FR-010.
Post-002 changes to any signature in this file require an explicit
spec amendment.

All types are opaque (Scala 3 `opaque type`) so the only constructors
are the named factories below. Constructors that validate input
return `Either[Error, T]`; constructors that cannot fail return `T`.

```scala
package siida.crypto.api

import java.security.SecureRandom

// ───────────────────────────────────────────────────────────────────────
// IBE
// ───────────────────────────────────────────────────────────────────────

opaque type MasterKey       = ... // PKG-only, never serialised by this module
opaque type MasterPublicKey = ... // distributable
opaque type IdentityKey     = ... // per-recipient, held by client
opaque type Ciphertext      = ... // serialisable

object IBE:
  /** Fresh master key. RNG must be cryptographically strong. */
  def generateMasterKey(rng: SecureRandom): MasterKey

  /** The public half. Safe to distribute. */
  def publicKey(mk: MasterKey): MasterPublicKey

  /** PKG-side: derive a per-identity decryption key. */
  def issueKey(mk: MasterKey, identity: Array[Byte]): IdentityKey

  /** Encrypt to an identity under a known master public key. */
  def encrypt(
    mpk:      MasterPublicKey,
    identity: Array[Byte],
    message:  Array[Byte],
    rng:      SecureRandom,
  ): Ciphertext

  /** Decrypt with a key issued for the same identity. */
  def decrypt(idk: IdentityKey, ct: Ciphertext): Either[IBEError, Array[Byte]]

  // Serialisation. Round-trip stable; bytes are canonical (no JSON, no padding).
  def serialiseMasterPublicKey(mpk: MasterPublicKey): Array[Byte]    // 32 bytes
  def deserialiseMasterPublicKey(bytes: Array[Byte]): Either[IBEError, MasterPublicKey]

  def serialiseIdentityKey(idk: IdentityKey): Array[Byte]            // 64 + len(id) bytes
  def deserialiseIdentityKey(bytes: Array[Byte]): Either[IBEError, IdentityKey]

  def serialiseCiphertext(ct: Ciphertext): Array[Byte]               // 48 + len(message) bytes
  def deserialiseCiphertext(bytes: Array[Byte]): Either[IBEError, Ciphertext]

enum IBEError:
  case InvalidKey
  case InvalidPoint
  case MalformedCiphertext(reason: String)
  case WrongIdentity     // identityTag mismatch on decrypt; no plaintext leakage
  case DecryptionFailed  // KDF/XOR produced inconsistent output; refuse silently

// ───────────────────────────────────────────────────────────────────────
// BLS
// ───────────────────────────────────────────────────────────────────────

opaque type BLSPrivateKey     = ...
opaque type BLSPublicKey      = ...
opaque type BLSSignature      = ... // carries Single/Aggregate kind internally
opaque type ProofOfPossession = ...

object BLS:
  def generateKeyPair(rng: SecureRandom): (BLSPrivateKey, BLSPublicKey)
  def publicKey(sk: BLSPrivateKey): BLSPublicKey

  /** Sign a message. */
  def sign(sk: BLSPrivateKey, message: Array[Byte]): BLSSignature

  /** Verify a single signature. */
  def verify(pk: BLSPublicKey, message: Array[Byte], sig: BLSSignature): Boolean

  /** Aggregate independent signatures. Empty list returns Left. */
  def aggregate(sigs: Seq[BLSSignature]): Either[BLSError, BLSSignature]

  /**
   * Verify an aggregate signature over the SAME message by multiple
   * signers. Requires a valid ProofOfPossession for every public key
   * to defend against rogue-key attacks.
   */
  def verifyAggregate(
    pks:     Seq[BLSPublicKey],
    pops:    Seq[ProofOfPossession],
    message: Array[Byte],
    aggSig:  BLSSignature,
  ): Boolean

  /**
   * Verify an aggregate signature over DISTINCT messages. Messages
   * must be pairwise distinct; we do not require PoPs here because
   * distinct-message verification is already rogue-key-safe.
   */
  def verifyAggregateDistinct(
    pkMsgPairs: Seq[(BLSPublicKey, Array[Byte])],
    aggSig:     BLSSignature,
  ): Boolean

  /** Produce a proof-of-possession for the signer's own public key. */
  def proofOfPossession(sk: BLSPrivateKey): ProofOfPossession

  /** Verify a proof-of-possession against the claimed public key. */
  def verifyPoP(pk: BLSPublicKey, pop: ProofOfPossession): Boolean

  // Serialisation
  def serialisePublicKey(pk: BLSPublicKey): Array[Byte]              // 32 bytes
  def deserialisePublicKey(bytes: Array[Byte]): Either[BLSError, BLSPublicKey]

  def serialisePrivateKey(sk: BLSPrivateKey): Array[Byte]            // 32 bytes
  def deserialisePrivateKey(bytes: Array[Byte]): Either[BLSError, BLSPrivateKey]

  def serialiseSignature(sig: BLSSignature): Array[Byte]             // 65 bytes (1 kind + 64 G2)
  def deserialiseSignature(bytes: Array[Byte]): Either[BLSError, BLSSignature]

  def serialisePoP(pop: ProofOfPossession): Array[Byte]              // 65 bytes
  def deserialisePoP(bytes: Array[Byte]): Either[BLSError, ProofOfPossession]

enum BLSError:
  case InvalidKey
  case InvalidPoint
  case InvalidSignature
  case InvalidPOP
  case EmptyAggregation
  case DistinctMessageRequired  // verifyAggregateDistinct given duplicate messages

// ───────────────────────────────────────────────────────────────────────
// BN254 (US3) — lower-level primitives for future modules
// ───────────────────────────────────────────────────────────────────────

opaque type Scalar    = ... // 32-byte big-endian, reduced mod r
opaque type G1Point   = ... // 32-byte compressed
opaque type G2Point   = ... // 64-byte compressed
opaque type GTElement = ... // 384-byte

object BN254:
  // Generators
  val G1Generator: G1Point
  val G2Generator: G2Point

  // Scalars
  def scalarFromBytes(bytes: Array[Byte]): Scalar           // reduces mod r; never fails
  def scalarToBytes(s: Scalar): Array[Byte]                 // canonical 32 bytes
  def scalarRandom(rng: SecureRandom): Scalar

  // Group ops
  def g1ScalarMul(s: Scalar, p: G1Point): G1Point
  def g2ScalarMul(s: Scalar, p: G2Point): G2Point
  def g1Add(a: G1Point, b: G1Point): G1Point
  def g2Add(a: G2Point, b: G2Point): G2Point

  // Pairings
  def pairing(p: G1Point, q: G2Point): GTElement
  def pairingCheck(pairs: Seq[(G1Point, G2Point)]): Boolean  // ∏ e(pi, qi) == 1

  // Hashing to G2 (SSWU; suite suffix MUST come from caller)
  def hashToG2(message: Array[Byte], domainSeparationTag: Array[Byte]): G2Point

  // Serialisation (round-trip stable; subgroup-checked on deserialise)
  def serialiseG1(p: G1Point): Array[Byte]                  // 32 bytes
  def deserialiseG1(bytes: Array[Byte]): Either[BN254Error, G1Point]
  def serialiseG2(p: G2Point): Array[Byte]                  // 64 bytes
  def deserialiseG2(bytes: Array[Byte]): Either[BN254Error, G2Point]

enum BN254Error:
  case InvalidEncoding
  case PointNotOnCurve
  case PointNotInSubgroup
```

## Contract guarantees

1. **Stability** (FR-010): no symbol in this file changes signature
   between 002 merging and the next constitution amendment to the
   crypto layer. Renames, parameter reorderings, return-type
   changes — all require a fresh spec.
2. **Determinism** (FR-004, FR-006): for fixed-seed RNG, every
   operation produces bit-identical output across Linux/amd64 and
   macOS/arm64.
3. **No side channels** (FR-012): no logging, no exceptions on
   secret-data branches, no telemetry. `IBEError.DecryptionFailed`
   and `IBEError.WrongIdentity` both return without revealing
   anything about *why* decryption failed beyond the typed tag.
4. **Typed errors** (FR-005): expected failure modes return
   `Either[Error, T]`. Exceptions are reserved for programming bugs
   (e.g., passing a 31-byte scalar where 32 is required) and
   irrecoverable resource failures (e.g., native library failed to
   load at startup).
5. **Serialisation canonicality**: every `serialise` ∘ `deserialise`
   round-trip returns a byte-identical object. Wire-format
   compatibility with the original Vuvuzela `crypto/ibe` and
   `crypto/bls` packages is NOT a goal of 002 (pre-alpha clean
   break, per `spec.md` Assumptions).
