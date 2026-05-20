# Contract: Mixnet Wire Format

**Feature**: [spec.md](../spec.md) · [research R4, R5, R6](../research.md)

## OnionLayer (between mixers)

The wire bytes between any two mixers in the chain are exactly
`HybridOnion.OnionLayer` bytes:

```
offset  size       field
0       1          algorithm ID (0x01 — hybrid v1, per spec 012)
1       32         x25519 ephemeral public key
33      1088       ML-KEM-768 ciphertext
1121    16         ChaCha20-Poly1305 tag (last bytes of AEAD ct+tag)
1137    *          AEAD ciphertext (variable, contains next layer)
```

Total: `1137 + |inner-ciphertext|` bytes.

The `|inner-ciphertext|` for layer k (k = 1..M-1) is the wire
length of layer k+1; for the last layer (k = M) it's the wire
length of the `MailboxEnvelope` it wraps.

## MailboxEnvelope (innermost payload)

After the last mixer's peel, the inner bytes are a
`MailboxEnvelope`:

```
offset  size  field
0       8     mailbox_id (uint64 big-endian)
8       *    opaque payload bytes
```

Total: `8 + |payload|`.

### Reserved mailbox-id values

| ID                    | Meaning                                          | Status |
|-----------------------|--------------------------------------------------|--------|
| `0x0000000000000000`  | Cover-traffic sink (PKG-controlled, discarded)   | Current |
| `0x0001..0xFFFE`       | Real mailbox IDs, allocated by the PKG (spec 005) | Allocated |
| `0xFFFFFFFFFFFFFFFF`  | Reserved for future "broadcast" semantics        | Reserved |

## Layered onion structure

A submission is built bottom-up: start with the inner
`MailboxEnvelope`, encrypt under the last mixer's public bundle
to get layer M-1's payload, encrypt that under mixer M-1's public
bundle to get layer M-2's payload, etc. The outermost wire bytes
are layer 1 — what the client submits to the coordinator.

For an M-mixer chain and a P-byte mailbox payload, total
submission size is:

```
M × 1137 + 8 + P
```

For M=3, P=256: 3×1137 + 8 + 256 = 3675 bytes per submission.

## Cover traffic

A cover submission has:

```
mailbox_id = 0 (CoverMailboxId)
payload    = P bytes from CSPRNG (rng.nextBytes)
```

…and is layered identically to a real submission. The on-wire
total length is identical; no per-byte fingerprint reveals it as
cover. The cover-mailbox-id holder (the PKG, per spec 005)
discards the contents on arrival.

## Drop semantics

A mixer that fails to decrypt its layer **does not emit a
placeholder**; the submission simply doesn't appear in the next
hop's batch. From a wire perspective:

- A round with N submissions in and N-2 successful first-mixer
  peels emits N-2 OnionLayer envelopes to mixer #2's input.
- A passive observer sees the batch size shrink by one for each
  drop. The shape information (how many drops) is observable;
  *which* submission was dropped is not (since the mixer
  shuffled before any drops could be correlated by position).

This is by design (research R8 / spec FR-004): silent drop
preserves submission-level confidentiality at the cost of
revealing aggregate drop rates. Aggregate metrics are acceptable
under the Vuvuzela threat model.
