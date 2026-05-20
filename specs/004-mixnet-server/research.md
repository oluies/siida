# Phase 0 Research: Mixnet Server

**Feature**: [spec.md](./spec.md)
**Date**: 2026-05-20
**Status**: Complete

## R1. Round-based mix-chain architecture (Vuvuzela)

The Vuvuzela design (Lazar et al., SOSP 2015) is the reference:

- **Coordinator** opens a round every T seconds (typically 60s in
  Vuvuzela). All clients submit exactly one layered ciphertext.
- **Mixer chain** of M servers (Vuvuzela used 3). Each mixer
  decrypts one layer of the onion and shuffles the batch.
- **Output**: a set of `(mailbox_id, ciphertext)` pairs delivered
  to a dead-drop store. Recipients poll their mailboxes.
- **Cover traffic**: every client always submits, real or noise.
  This is what makes the metadata-privacy guarantee work — a
  passive observer sees N submissions every round regardless of
  actual communication patterns.

Siida adopts this architecture verbatim with one substitution:
the per-layer encryption is `HybridOnion` (PQ-hybrid ML-KEM-768 +
x25519) instead of NaCl `box`.

## R2. Why no verifiable shuffle

Mixnet literature has proven-correct shuffle schemes
(Neff '01, Furukawa-Sako '01, etc.) where each mixer outputs a
zero-knowledge proof that the shuffle was correctly performed
without revealing the permutation. Vuvuzela explicitly skips
these because:

1. **Threat model**: Vuvuzela's security goal is metadata privacy
   under a passive global adversary + a malicious minority of
   mixers. A malicious mixer who decides not to shuffle correctly
   can only break liveness (drop/duplicate submissions); it
   cannot break confidentiality of the messages.
2. **Performance**: verifiable shuffle adds 10-100× CPU per round.
3. **Implementation complexity**: ZK shuffle is non-trivial
   crypto-engineering work and adds an attack surface.

Siida inherits this trade-off. 004 implements a plain Fisher-
Yates shuffle seeded from a per-round per-mixer CSPRNG draw. The
seed is publishable (or zeroised) post-round to allow audit
without ZK machinery.

## R3. Shuffle determinism for tests

A pure deterministic shuffle from a fixed seed is necessary for
the FR-003 "Coordinator.runRound is a pure function" contract.
Implementation:

```scala
def shuffle[A](arr: Array[A], seed: Array[Byte]): Array[A] = {
  // Fisher-Yates from a SHA1PRNG seeded with the 32-byte seed
  val rng = SecureRandom.getInstance("SHA1PRNG")
  rng.setSeed(seed)
  val out = arr.clone()
  for i in (out.length - 1) until 0 by -1 do
    val j = rng.nextInt(i + 1)
    val tmp = out(i); out(i) = out(j); out(j) = tmp
  out
}
```

This produces a bit-stable shuffle on every JVM that ships
SHA1PRNG (i.e., all of them, per the Java standard).

## R4. Layer-peeling semantics

Each `HybridOnion.OnionLayer` envelope is 1137 bytes of fixed
overhead + N bytes of inner payload. When mixer #k decrypts its
layer, the AEAD plaintext IS the next layer's `OnionLayer` wire
bytes (or, for the last mixer, the innermost mailbox-id +
payload tuple).

```
Client submission:
  L_1 = encrypt(mixer_1_pk, L_2)
  L_2 = encrypt(mixer_2_pk, L_3)
  L_3 = encrypt(mixer_3_pk, MailboxEnvelope(mailbox_id, payload))

Mixer #1 processing:
  decrypt(mixer_1_sk, L_1) → L_2 wire bytes (1137 + |L_3|)

Mixer #2:
  decrypt(mixer_2_sk, L_2) → L_3 wire bytes

Mixer #3 (last):
  decrypt(mixer_3_sk, L_3) → MailboxEnvelope bytes
```

The wire format between mixers is **just `OnionLayer` bytes** —
no extra framing (FR-006). The structure is self-describing: a
mixer doesn't know whether its output is another `OnionLayer` or
a `MailboxEnvelope` until it tries to parse it (which is the
final-mixer's responsibility).

## R5. Mailbox envelope

The innermost payload is a `MailboxEnvelope`:

```
offset  size      field
0       8         mailbox_id (uint64 big-endian)
8       *         opaque payload bytes
```

Total: `8 + |payload|`. The mailbox_id is a routing key into the
dead-drop store; the payload is opaque to 004 (typically an
`IdentityCiphertext` from 015 for end-to-end messages, but 004
doesn't care).

## R6. Cover-traffic design

A cover submission targets a "dummy" mailbox (the PKG-controlled
sink, mailbox_id = 0 by convention) with a random inner payload.
On-wire indistinguishable from a real submission:
- Same 1137-byte HybridOnion overhead per layer
- Same N layers
- Same total wire length (`N × 1137 + 8 + |payload|`)

The cover-mailbox holder (the PKG, per spec 005) discards all
arrivals. 004 doesn't need to know about this — cover and real
flow through the chain identically.

## R7. Why Pekko Streams (not just collections)?

For a single-JVM MVP, in-memory collection operations are
sufficient. We could implement `Coordinator.runRound` as:

```scala
def runRound(submissions: List[Bytes], chain: List[Mixer]): RoundResult =
  chain.foldLeft(submissions) { (batch, mixer) =>
    mixer.shuffle(batch.flatMap(mixer.peel))
  }
```

Pekko Streams adds:
- Future-proofing: when a follow-up spec adds network
  transport, the same `Flow[OnionLayer, OnionLayer]` per mixer
  becomes a remote source/sink without rewriting the chain
  topology
- Backpressure: a slow mixer doesn't OOM the upstream queue
- Structured concurrency around the round timer

For 004's MVP, we use Pekko Streams **for the per-mixer pipeline
stages** (Source → Flow → Sink) but keep `Coordinator.runRound`
as a synchronous pure function that internally materialises and
awaits the stream. Tests stay deterministic; production deployment
gains the streaming surface without re-architecting.

## R8. Error model: drop-not-throw

Per FR-004, a mixer that fails to decrypt a layer drops the
submission silently. The mixer's `peel` returns
`Option[OnionLayer]`:
- `Some(next)` — successful peel, forward
- `None` — wire-format error or decryption failure, drop

This is a deliberate design choice: a propagated error would let
an adversary fingerprint which submissions in a batch are
corrupted by observing the error rate. Silent drop preserves the
batch-shape information-theoretically.

## R9. Mailbox-id space

64-bit unsigned integer, big-endian on the wire. Reserved values:
- `0x0000000000000000` — cover-traffic sink (PKG-controlled,
  contents discarded)
- `0xFFFFFFFFFFFFFFFF` — reserved for future "broadcast" semantics
- All other values — opaque routing keys assigned by the PKG
  (spec 005's concern)

004 doesn't allocate mailboxes; it just routes by ID.

## R10. What 004 does NOT cover

- **Round timer**: when to open / close a round. 004's
  `Coordinator.runRound` takes a pre-collected batch as input;
  the SDK (007) + a future "live coordinator" spec handle
  timing.
- **Network protocol**: client→coordinator and mixer→mixer
  transports. 004 is in-process Pekko Streams.
- **Persistent state**: an in-flight round is in-memory only.
- **Roster rotation**: live mixer-key changes during operation.
- **Sybil resistance**: spec 005 (PKG) controls identity
  onboarding; 004 takes the roster as configuration.
- **Crash recovery**: a crashed mixer mid-round loses its batch;
  follow-up spec adds checkpointing.
- **Performance optimisation**: cores, thread pools, memory
  pooling. 004 hits the SC-004 ≤500 ms target without tuning.

## R11. Reference: Vuvuzela's `crypto/onionbox`

The Go upstream's onionbox primitive is structurally identical
to Siida's `HybridOnion` API. Siida's MixChain.layeredSubmission
maps 1:1 to Vuvuzela's `onionbox.Seal` — the only difference is
that the per-layer KEM is PQ-hybrid instead of classical NaCl.
The shuffle and chain semantics are byte-compatible at the
algorithm level.
