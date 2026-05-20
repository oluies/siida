# Contract: Public Scala API of `siida.pkg.api.Friendship` + `siida.pkg.api.FriendStore`

**Feature**: [spec.md](../spec.md) · **Stability gate**: FR-009

```scala
package siida.pkg.api

import java.security.SecureRandom
import siida.crypto.api.{Directory, HybridOnion}

object Friendship:

  opaque type AddRequest = Array[Byte]

  /** Wire-format alg-ID for this spec's add-request variant. */
  object AlgorithmID:
    val AddRequest_v1: Byte = 0x30.toByte

  /** The plaintext content carried inside an AddRequest. Bob
   *  receives this after decrypting; he then verifies the
   *  binding against the PKG directory.
   */
  final case class AddRequestContent(
    senderIdentity:     Array[Byte],
    senderPublicBundle: HybridOnion.HybridPublicBundle,
  )

  /** Alice constructs an add-request to bob. Encrypts the
   *  (alice_identity, alice_public_bundle) payload under bob's
   *  public bundle via HybridOnion.encrypt. Output is the
   *  ciphertext alice sends to bob (out-of-scope: how).
   */
  def buildAddRequest(
    senderIdentity:        Array[Byte],
    senderPublicBundle:    HybridOnion.HybridPublicBundle,
    recipientPublicBundle: HybridOnion.HybridPublicBundle,
    rng:                   SecureRandom,
  ): AddRequest

  /** Bob receives an add-request, decrypts it with his secret
   *  bundle, and recovers the claimed content. This step is
   *  CRYPTOGRAPHIC verification only — the binding-truth check
   *  is in `verifyAddRequest`.
   */
  def processAddRequest(
    recipientSecret: HybridOnion.HybridSecretBundle,
    ct:              AddRequest,
  ): Either[FriendshipError, AddRequestContent]

  /** Bob verifies that the claimed identity actually maps to the
   *  claimed public bundle in his current directory snapshot.
   *  This is the load-bearing trust step (SC-006).
   */
  def verifyAddRequest(
    content:   AddRequestContent,
    directory: Directory,
  ): Either[FriendshipError, Unit]

  def serialiseAddRequest(req: AddRequest): Array[Byte]

  def deserialiseAddRequest(bytes: Array[Byte]): Either[FriendshipError, AddRequest]


/** Local cache of accepted friends. Lookup by identity returns
 *  the friend's public bundle, letting the SDK encrypt without
 *  hitting the PKG directory (and thus without leaking the
 *  friendship to the PKG via lookup pattern).
 */
trait FriendStore:

  /** Add an accepted friend. Returns `false` if the identity
   *  was already present (idempotent re-add); `true` if newly
   *  added.
   */
  def add(
    identity: Array[Byte],
    bundle:   HybridOnion.HybridPublicBundle,
  ): Boolean

  def lookup(identity: Array[Byte]): Option[HybridOnion.HybridPublicBundle]

  /** Enumerate the identities currently in the store. Order
   *  is insertion order.
   */
  def list(): Seq[Array[Byte]]


object FriendStore:

  /** Construct a fresh in-memory FriendStore. */
  def inMemory(): FriendStore
```

Add to `siida.pkg.api.Errors`:

```scala
enum FriendshipError derives CanEqual:
  case InvalidLength
  case UnsupportedAlgorithm
  case DecryptionFailed
  case MalformedRequest(reason: String)
  case IdentityNotInDirectory
  case IdentityMismatch
```

## Contract guarantees

1. **Stability** (FR-009): all signatures in this file are
   locked post-019 merge.
2. **Verification consults only the directory** (SC-006):
   `verifyAddRequest` uses the directory's binding as the source
   of truth. The claimed bytes-in-the-ciphertext are NEVER
   self-attesting.
3. **`processAddRequest` is total** — returns `Left(...)` on any
   per-call failure, no throws.
4. **Uniform alg-ID refusal** (FR-007): same
   `UnsupportedAlgorithm` for any non-`0x30` first byte.
5. **`FriendStore.add` is idempotent**: re-adding the same
   identity returns `false` and does not mutate the bundle.

## Wire formats

See `contracts/wire-format.md` for the byte layout. Summary:

| Type | Total | Layout |
|---|---|---|
| `AddRequest` (ciphertext) | `1138 + payload` bytes | 1-byte alg-ID (0x30) + HybridOnion.OnionLayer |
| `AddRequestContent` (plaintext) | `1218 + sender_identity_len` bytes | 2-byte ID length + ID bytes + 1216-byte HybridPublicBundle |

The OnionLayer's inner payload IS the AddRequestContent bytes.
Total ciphertext size: `1 + 1137 + 1218 + sender_identity_len` =
`2356 + sender_identity_len` bytes.

## What's NOT here

- **No `Friendship.buildAddResponse`** — out-of-scope (separate
  follow-up spec)
- **No `FriendStore.remove`** — out-of-scope (revocation in a
  separate spec)
- **No `FriendStore.persist` / `loadFrom`** — in-memory only
- **No friendship-key derivation** — separate spec
- **No mixnet integration** — that's `MixChain.layeredSubmission`
  in spec 004; SDK (007) composes them
