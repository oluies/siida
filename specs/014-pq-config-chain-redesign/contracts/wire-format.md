# Contract: Multi-Signed Entry Wire Format

**Feature**: [spec.md](../spec.md) · [research R5](../research.md)

This document pins the byte-level layout of a `MultiSignedEntry`.
Spec 006 consumes this format directly; any change requires a
follow-up spec.

## Layout (FormatVersion 0x01)

```
offset                size      field
─────────────────────  ────────  ────────────────────────────────────
0                     1         FormatVersion (0x01)
1                     2         signature count `n` (uint16 big-endian)
3                     n × 3312  signature tuples: each =
                                  2-byte signer_index (uint16 BE) +
                                  3310-byte PqSignature wire envelope
3 + n×3312            32        SHA3-256(payload)
3 + n×3312 + 32       *         payload bytes (opaque; 006 defines)
```

**Total bytes** = `35 + n × 3312 + |payload|`.

For n = 8: `35 + 26,496 + |payload| ≈ 26.5 KB + |payload|`.

> **Note on actual signature size**: FIPS 204 Table 1 gives ML-DSA-65
> signatures as 3309 bytes (NOT 3293 as earlier draft tables of this
> contract stated). The PqSignature wire envelope from spec 013 is
> therefore `1 + 3309 = 3310` bytes, and the per-tuple wire size is
> `2 + 3310 = 3312` bytes. The implementation in
> `MultiSignedEntry.scala` exports the constant `TupleWireBytes = 3312`
> for downstream consumers.

## Field semantics

### FormatVersion (1 byte)

- `0x01` — this spec's layout (per-signer ML-DSA-65 with
  PqSignature wire envelope from 013).
- `0x02`–`0x7F` — reserved for future format bumps (e.g., when PQ
  multisignatures mature).
- `0x80`–`0xFF` — reserved for experimental / testing.

A verifier seeing an unknown version byte returns
`MultiSignedEntryError.UnsupportedVersion`. The error MUST NOT
reveal which versions are supported.

### Signature count `n` (2 bytes, uint16 big-endian)

Number of `(signer_index, PqSignature)` tuples in the next section.
Values 0–65535. The empty case (n = 0) is permitted in the wire
format but `verify` will return `ThresholdNotMet(0, threshold)`
for it.

### Signature tuples (n × 3312 bytes each)

Each tuple is:

```
2 bytes    signer_index (uint16 big-endian) — index into the roster
3310 bytes PqSignature wire envelope (1-byte alg ID + 3309-byte
           ML-DSA-65 signature) per spec 013's wire format
```

**No canonical ordering** is required — `verify` sorts by
`signer_index` internally. Wire bytes from different signers can
arrive in any order.

**Duplicate signer_index values** are rejected at verify time
with `DuplicateSigner(index)`. The wire format permits them
syntactically; the verifier enforces the policy.

### Payload hash (32 bytes)

SHA3-256 hash of the payload bytes (the field that follows).

The verifier **MUST** recompute this hash from the payload and
compare; trusting the wire field directly is wrong (an attacker
could substitute payloads).

Including the hash field as part of the on-wire envelope is a
convenience: streaming-style verifiers (e.g., 016 observability
consumers checking governance entries) can read the hash without
materialising the full payload. They recompute on demand if they
need to validate.

### Payload bytes (variable)

Opaque to 014. Spec 006 defines the structure: probably a
length-prefixed CBOR/protobuf blob containing roster changes,
PKG key publications, epoch markers, etc.

## Signed-message construction

What each signer signs:

```
signed_message = SHA3-256(payload_bytes) || domain_separation_tag
```

The domain-separation tag is a per-chain ASCII string (e.g.,
`"siida/config-chain/v1/mainnet"`). Spec 006 sets it; 014 just
requires that it be passed to `verify`.

Verifier algorithm:

```
def verify(roster, threshold, dst, entry):
    1. unpack entry → version + n + signatures + recorded_hash + payload
    2. recompute hash = SHA3-256(payload)
    3. if recorded_hash != hash → PayloadHashMismatch
    4. build signed_message = recorded_hash || dst
    5. sort signatures by signer_index
    6. check for duplicates → DuplicateSigner(idx) if any
    7. check each signer_index is in [0, len(roster)) → InvalidSignerIndex(idx) if not
    8. build batchVerify input: ((roster[idx], signed_message, sig) for each tuple)
    9. result = PqSignature.batchVerify(batch_input)
   10. if result is false → at least one sig invalid; count valid by sequential verify
       (returns ThresholdNotMet(count, threshold) if count < threshold)
   11. if all signatures valid AND len(signatures) >= threshold → Valid
   12. otherwise → ThresholdNotMet(len(signatures), threshold)
```

Step 10's fallback to sequential verify on batch-fail is needed
because `batchVerify` returns `false` if ANY sig is invalid
without revealing which — so we have to retry sequentially to
count the valid ones for the `ThresholdNotMet` accurate count.

## Size comparison vs classical aggregate

| Format | 8-signer entry size | Note |
|---|---|---|
| Classical BLS aggregate (Vuvuzela / Alpenhorn) | 32 + 65 + payload | Single aggregate sig + roster manifest |
| 014 per-signer ML-DSA | 35 + 26,496 + payload | Linear in N; trade for PQ security |

The ~400× size growth is acceptable for governance traffic
(config updates are infrequent). If real-world deployment shows
this becoming a bottleneck, a future spec may explore PQ
multisignature schemes — research-stage as of 2026-05.
