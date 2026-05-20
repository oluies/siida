# Contract: Public Scala API of `siida.crypto.api.MultiSignedEntry`

**Feature**: [spec.md](../spec.md) · **Stability gate**: FR-010

```scala
package siida.crypto.api

object MultiSignedEntry:

  opaque type Entry = ...   // wire-format bytes, version-tagged

  /** Verify an entry against a roster and threshold. Pure function. */
  def verify(
    roster:               Seq[PqSignature.PqPublicKey],
    threshold:            Int,
    domainSeparationTag:  Array[Byte],
    entry:                Entry,
  ): VerifyResult

  /** Construct an entry from a payload and a set of signatures.
   *  Signers are presumed to have already signed
   *  `SHA3-256(payload) || domain_separation_tag` via PqSignature.sign.
   *
   *  Builders are typically the 006 config-chain machinery; 014
   *  exposes this constructor for tests and for emergency
   *  out-of-band signing tools.
   */
  def assemble(
    payload:    Array[Byte],
    signatures: Seq[(Int, PqSignature.Signature)],  // (signer_index, sig)
  ): Either[MultiSignedEntryError, Entry]

  // ── Serialisation ────────────────────────────────────

  def serialiseEntry(entry: Entry): Array[Byte]

  def deserialiseEntry(bytes: Array[Byte]): Either[MultiSignedEntryError, Entry]

  // ── Constants ───────────────────────────────────────

  /** Wire-format version tag for this spec. */
  val FormatVersion: Byte = 0x01

  /** Signed-message construction: caller computes
   *  SHA3-256(payload) || domainSeparationTag before invoking
   *  PqSignature.sign. The helper is exposed for completeness.
   */
  def signedMessage(payload: Array[Byte], domainSeparationTag: Array[Byte]): Array[Byte]


enum VerifyResult derives CanEqual:
  case Valid
  case ThresholdNotMet(validCount: Int, required: Int)
  case DuplicateSigner(index: Int)
  case InvalidSignerIndex(index: Int)
  case PayloadHashMismatch
  case MalformedEntry(reason: String)
```

Add to `siida.crypto.api.Errors`:

```scala
enum MultiSignedEntryError derives CanEqual:
  case InvalidLength
  case UnsupportedVersion
  case DuplicateSignerIndex(index: Int)
  case InvalidSignatureCount(count: Int)
  case MalformedBytes(reason: String)
```

## Contract guarantees

1. **Stability** (FR-010): every signature in this file is locked
   post-014 merge.
2. **Verifier is a pure function**: same inputs → same
   `VerifyResult`. No clock, no network, no global state.
3. **Tolerant of signer-list reordering**: `verify` sorts by
   `signer_index` internally; the entry's wire bytes are not
   required to be in any particular order.
4. **Intolerant of duplicate signers**: `verify` returns
   `DuplicateSigner(index)` if any signer_index appears twice.
5. **Per-chain domain separation**: each chain instance passes a
   distinct `domainSeparationTag`; a signature valid for chain A's
   tag is NOT valid for chain B's tag. Spec 006 owns tag selection.
6. **Threshold uses `PqSignature.batchVerify`**: a single batched
   invocation drives the cryptographic check, with ~0.6n verify
   work for n distinct signatures (research R3 of spec 013).

## Stability and compatibility

- The `FormatVersion = 0x01` byte at the head of every entry lets
  a future spec introduce a v2 format (e.g., a smaller
  per-signature variant if PQ multisig schemes mature) without
  breaking existing entries.
- The `Entry` opaque type wraps validated wire bytes; an `Entry`
  value is always a parseable, version-1-compliant envelope.
- `VerifyResult` is an exhaustive `enum`; pattern-matching on it
  is complete and compiler-checked.
