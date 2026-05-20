# Contract: Public Scala API of `siida.crypto.api.IdentityEncryption`

**Feature**: [spec.md](../spec.md) · **Stability gate**: FR-010

```scala
package siida.crypto.api

import java.security.SecureRandom

object IdentityEncryption:

  opaque type IdentityCiphertext = ...  // wire: 0x20 + HybridOnion.OnionLayer

  // ── Encrypt / Decrypt ──────────────────────────────────

  /** Look up `identity` in `directory`, verify the entry's
   *  signature against the PKG roster, then HybridOnion-encrypt
   *  the message to the recipient's bundle.
   */
  def encrypt(
    directory: Directory,
    identity:  Array[Byte],
    message:   Array[Byte],
    rng:       SecureRandom,
  ): Either[IdentityEncError, IdentityCiphertext]

  /** Decrypt with the recipient's hybrid secret bundle. Inherits
   *  HNDL-resistance from HybridOnion.decrypt.
   */
  def decrypt(
    secret: HybridOnion.HybridSecretBundle,
    ct:     IdentityCiphertext,
  ): Either[IdentityEncError, Array[Byte]]

  // ── Serialisation ────────────────────────────────────

  def serialiseCiphertext(ct: IdentityCiphertext): Array[Byte]
  def deserialiseCiphertext(bytes: Array[Byte]): Either[IdentityEncError, IdentityCiphertext]

  // ── Constants ───────────────────────────────────────

  object AlgorithmID:
    val IdentityEncryption_v1: Byte = 0x20.toByte
    // 0x21+ reserved for future identity-encryption variants


/** Opaque directory abstraction. Spec 005 (PKG) provides the
 *  persistent / network-backed implementation; 015 defines the
 *  trait and an `InMemoryDirectory` for tests.
 */
trait Directory:

  /** Look up an identity. The returned bundle is signature-verified
   *  against the PKG roster the directory was constructed with;
   *  callers can rely on `lookup`'s Right path being a trusted
   *  binding.
   */
  def lookup(identity: Array[Byte]): Either[IdentityEncError, HybridOnion.HybridPublicBundle]


object Directory:
  /** Build a Directory backed by an in-memory map. Each entry must
   *  carry a `MultiSignedEntry` proof attesting the
   *  `identity → bundle` binding; the directory verifies the
   *  proof against `roster` and `threshold` at lookup time.
   */
  def inMemory(
    entries:             Map[IArray[Byte], (HybridOnion.HybridPublicBundle, MultiSignedEntry.Entry)],
    roster:              Seq[PqSignature.PqPublicKey],
    threshold:           Int,
    domainSeparationTag: Array[Byte],
  ): Directory
```

Add to `siida.crypto.api.Errors`:

```scala
enum IdentityEncError derives CanEqual:
  case IdentityNotFound
  case InvalidDirectorySignature
  case UnsupportedAlgorithm
  case InvalidLength
  case DecapsulationFailed
  case MalformedCiphertext(reason: String)
```

## Contract guarantees

1. **Stability** (FR-010): every signature in this file is locked
   post-015 merge.
2. **HNDL-resistance** (FR-006): `decrypt` inherits 012's HNDL
   property — a quantum adversary with the recipient's x25519 sk
   (Shor-recovered) but not their ml_kem sk cannot decrypt.
3. **Directory integrity** (FR-005): `encrypt` verifies the
   directory entry's `MultiSignedEntry` against the roster on
   every call. There is no opt-out.
4. **Identity-not-found is a per-call error**, not an exception
   (FR-004): callers get `Left(IdentityNotFound)`, no thrown
   exception, no fallback encryption.
5. **Uniform decapsulation errors**: `decrypt` collapses all
   per-call failures to `DecapsulationFailed` (FR-006 from 012
   inherited). The ciphertext shape (wrong recipient, wrong
   algorithm ID, tampered AEAD) all yield the same typed error;
   no side channel.

## Wire format

```
offset  size       field
0       1          algorithm ID (0x20 for this spec)
1       *          HybridOnion.OnionLayer wire bytes (1137 + payload)
```

Total: `1138 + |payload|` bytes per ciphertext.

See `contracts/wire-format.md` for the full breakdown.

## Stability and compatibility

- The `0x20` algorithm-ID byte lets a future PQ-IBE migration ship
  alongside this without breaking existing ciphertexts in flight.
- The `Directory` trait lets spec 005 substitute a real
  persistent/networked implementation without 015 / 007 / SDK
  consumers needing changes.
