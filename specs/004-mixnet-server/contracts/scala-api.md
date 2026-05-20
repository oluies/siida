# Contract: Public Scala API of `siida.mixnet.api.*`

**Feature**: [spec.md](../spec.md) · **Stability gate**: FR-010

```scala
package siida.mixnet.api

import java.security.SecureRandom
import siida.crypto.api.HybridOnion

object MixChain:

  /** Wire-encoded mailbox envelope: 8-byte big-endian mailbox_id
   *  + opaque payload bytes.
   */
  opaque type MailboxEnvelope = Array[Byte]

  /** Construct a `MailboxEnvelope` from a mailbox id and payload. */
  def envelope(mailboxId: Long, payload: Array[Byte]): MailboxEnvelope

  /** Read the mailbox-id from an envelope. */
  def envelopeMailboxId(env: MailboxEnvelope): Long

  /** Read the payload bytes from an envelope. */
  def envelopePayload(env: MailboxEnvelope): Array[Byte]

  /** Build a layered submission for a chain of mixers. The
   *  innermost layer wraps `envelope`; layer k wraps the
   *  encryption of layer k+1 under mixer k's public bundle.
   *  The output is the outermost `OnionLayer` wire bytes —
   *  what the client submits to the coordinator.
   */
  def layeredSubmission(
    chain:    Seq[HybridOnion.HybridPublicBundle],
    envelope: MailboxEnvelope,
    rng:      SecureRandom,
  ): HybridOnion.OnionLayer

  /** Cover-traffic submission targeting the reserved
   *  mailbox-id 0 with a randomised inner payload. On-wire
   *  indistinguishable from a real submission.
   */
  def coverSubmission(
    chain:      Seq[HybridOnion.HybridPublicBundle],
    payloadLen: Int,
    rng:        SecureRandom,
  ): HybridOnion.OnionLayer

  /** Reserved mailbox-ids. */
  val CoverMailboxId: Long      = 0L
  val BroadcastMailboxId: Long  = -1L  // 0xFFFF…FFFF as signed Long


object Mixer:

  /** Peel exactly one layer from an `OnionLayer`. Returns the
   *  inner bytes — these are either the next-layer `OnionLayer`
   *  wire bytes or the innermost `MailboxEnvelope` bytes; the
   *  caller (coordinator) decides which based on whether this
   *  mixer is the last in the chain. Returns `None` on any
   *  decryption failure or wire-format error (FR-004 silent drop).
   */
  def peel(
    secret: HybridOnion.HybridSecretBundle,
    layer:  HybridOnion.OnionLayer,
  ): Option[Array[Byte]]


object Coordinator:

  /** A single per-round result: ordered output set (mailbox_id,
   *  payload-bytes) plus per-mixer round metrics.
   */
  final case class RoundResult(
    deliveries: Vector[MixChain.MailboxEnvelope],
    metrics:    RoundMetrics,
  )

  /** Diagnostic metrics. No timing-side-channel — produced
   *  post-hoc from in-memory counters.
   */
  final case class RoundMetrics(
    submissionsIn:  Int,
    deliveriesOut:  Int,
    perMixerDrops:  Vector[Int],   // one entry per mixer in chain order
  )

  /** Run one mix round through the chain. PURE function modulo
   *  the crypto primitives: same inputs produce the same output
   *  byte-for-byte.
   *
   *  @param submissions   the batch of outermost OnionLayer bytes
   *                       received from clients (one per client)
   *  @param chainSecrets  mixer secret bundles, in chain order
   *                       (chainSecrets(0) is the first mixer
   *                       to process the batch)
   *  @param shuffleSeeds  per-mixer 32-byte seed; the mixer at
   *                       position k uses shuffleSeeds(k)
   */
  def runRound(
    submissions:   Seq[HybridOnion.OnionLayer],
    chainSecrets:  Seq[HybridOnion.HybridSecretBundle],
    shuffleSeeds:  Seq[Array[Byte]],
  ): RoundResult
```

Add to `siida.mixnet.api.Errors`:

```scala
package siida.mixnet.api

enum MixnetError derives CanEqual:
  case InvalidLength
  case MalformedEnvelope(reason: String)
  case ChainLengthMismatch(have: Int, want: Int)
  case ShuffleSeedSize(have: Int, want: Int)
```

## Contract guarantees

1. **Stability** (FR-010): all signatures in this file are locked
   post-004 merge. New variants get new methods, not signature
   changes.
2. **`runRound` is pure** modulo crypto — same `(submissions,
   chainSecrets, shuffleSeeds)` always produce the same
   `RoundResult` byte-for-byte (FR-003). The crypto operations
   themselves are deterministic per spec 013/015 (signing /
   encryption with fixed-seed RNGs in tests).
3. **Mixer.peel is total** — it returns `Option`, never throws on
   per-call failures. Programming errors (e.g., wrong-length
   buffer crossing the FFI) still throw, but per-submission
   crypto failures yield `None`.
4. **Wire format is HybridOnion all the way down** (FR-006): the
   bytes between mixers are valid `OnionLayer` envelopes; the
   bytes after the last mixer are valid `MailboxEnvelope`
   envelopes. No per-mixer framing.
5. **Cover traffic is indistinguishable** on-wire from real
   traffic (FR-007). Tests verify by byte-length and structural
   comparison.

## What's NOT here

- **No network transport** in 004's API. A follow-up spec adds
  `Coordinator.runRoundRemote` or a `NetworkedMixer` with TCP /
  gRPC plumbing.
- **No persistence** of in-flight rounds. Coordinator state is
  per-call only.
- **No timer / scheduler**. The SDK (spec 007) drives round
  timing.

## Stability and compatibility

The `siida.mixnet.api` package is now considered stable. Spec
007 (SDK) and spec 005 (PKG) compose against this surface; any
breaking change requires a follow-up spec.
