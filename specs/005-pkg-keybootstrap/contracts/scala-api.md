# Contract: Public Scala API of `siida.pkg.api.*`

**Feature**: [spec.md](../spec.md) · **Stability gate**: FR-008

```scala
package siida.pkg.api

import java.security.SecureRandom
import siida.crypto.api.{Directory, HybridOnion, MultiSignedEntry, PqSignature}

object Pkg:

  /** Build a new PKG. The roster is a list of (public, private)
   *  key pairs; the threshold is the M-of-N requirement. The
   *  `domainSeparationTag` is the per-chain DST passed to
   *  `MultiSignedEntry.verify` later by directory consumers; the
   *  PKG signs with the same DST so the bindings verify.
   *
   *  `initialMailboxId` is the first mailbox-id the allocator
   *  returns. Reserved IDs (0, -1) are skipped at allocation
   *  time regardless of this seed.
   */
  def create(
    rosterPublicKeys:    Seq[PqSignature.PqPublicKey],
    rosterPrivateKeys:   Seq[PqSignature.PqPrivateKey],
    threshold:           Int,
    domainSeparationTag: Array[Byte],
    initialMailboxId:    Long = 1L,
  ): Either[PkgError, Pkg]


trait Pkg:

  /** Issue a new identity. Generates a fresh HybridSecretBundle,
   *  allocates the next mailbox-id, signs the binding with the
   *  first `threshold` roster keys, and adds the entry to the
   *  directory.
   *
   *  Returns `Left(IdentityAlreadyExists)` if `identity` was
   *  previously issued. Programming errors (wrong-length roster
   *  keys, etc.) throw.
   */
  def issueIdentity(
    identity: Array[Byte],
    rng:      SecureRandom,
  ): Either[PkgError, IssuedIdentity]

  /** Pure-function read: a `Directory` reflecting the current
   *  PKG state. Multiple calls return semantically-equal
   *  Directory instances over the same state.
   */
  def directorySnapshot(): Directory


/** The PKG's response to an `issueIdentity` call. */
final case class IssuedIdentity(
  /** The user's secret bundle (must be delivered out-of-band). */
  secretBundle:  HybridOnion.HybridSecretBundle,
  /** The mailbox-id assigned to this identity. */
  mailboxId:     Long,
  /** The public bundle the directory entry signs over. Echoed
   *  back for the caller's verification convenience.
   */
  publicBundle:  HybridOnion.HybridPublicBundle,
  /** The MultiSignedEntry proof. */
  proof:         MultiSignedEntry.Entry,
)
```

Add `siida.pkg.api.Errors`:

```scala
enum PkgError derives CanEqual:
  case EmptyRoster
  case InvalidThreshold(threshold: Int, rosterSize: Int)
  case RosterKeyMismatch(have: Int, expected: Int)
  case IdentityAlreadyExists
  case MailboxIdExhausted
```

## Contract guarantees

1. **Stability** (FR-008): all signatures in this file are locked
   post-005 merge.
2. **`directorySnapshot` is a pure-function read** — same PKG
   state produces a Directory with the same lookup behaviour.
3. **PKG does not retain secret bundles** (FR-006-like; SC-006):
   `Pkg` keeps public bundles + proofs + mailbox-ids only. The
   issued secret bundle returned by `issueIdentity` is the
   caller's to hold.
4. **Reserved mailbox-ids are skipped**: 0 (cover) and -1
   (broadcast) are never returned by `issueIdentity` regardless
   of `initialMailboxId` configuration.
5. **Idempotent identity check**: `issueIdentity` for an
   already-issued identity returns `Left(IdentityAlreadyExists)`
   without mutating PKG state.
6. **Threshold signer choice** is signers `[0, threshold)` in
   roster order. (MVP — policy-driven selection is a follow-up.)

## Wire format

See `contracts/wire-format.md`. The directory-entry payload that
the PKG roster signs over is:

```
2 bytes  identity_length (uint16 BE)
N bytes  identity_bytes
8 bytes  mailbox_id (uint64 BE)
1216     public_bundle_wire_bytes (012 spec)
```

Total: `1226 + identity_length` bytes per directory entry payload.

## What's NOT here

- **No `Pkg.rotateRoster(...)`** — out of scope; consumes 006.
- **No `Pkg.revokeIdentity(...)`** — out of scope; separate spec.
- **No friend-discovery primitives** — out of scope; separate
  spec.
- **No persistent backing store interface** — out of scope.
