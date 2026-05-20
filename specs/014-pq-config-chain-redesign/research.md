# Phase 0 Research: PQ Config-Chain Redesign

**Feature**: [spec.md](./spec.md)
**Date**: 2026-05-20
**Status**: Complete

## R1. Why per-signer rather than aggregate

Per 011 R3 and 013 R2, no PQ aggregate signature is
production-grade. The realistic options for a multi-signer config
chain are:

| Option | Storage per entry | Verify cost | Production-ready? |
|---|---|---|---|
| BLS aggregate (classical) | 1 × ~64 B | 1 pairing-check | Yes — but quantum-vulnerable |
| Per-signer ML-DSA (this spec) | N × ~3294 B | `batchVerify(N)` ≈ ~0.6N × ~5 ms | Yes |
| Threshold ML-DSA / Multisig FROST-PQ | 1 × ~3294 B | 1 verify | No — research only |
| SLH-DSA per-signer | N × ~17 KB | N × ~100 ms | Yes, but expensive |

Per-signer ML-DSA + batch verify is the only production-grade
production-ready path that preserves M-of-N semantics.

## R2. Signed-message derivation

**Decision**:

```
signed_message = SHA3-256(payload_bytes) || domain_separation_tag
```

Where:
- `payload_bytes` is the 006-defined config entry payload, treated
  as opaque bytes here
- `domain_separation_tag` is a per-chain ASCII tag (e.g.,
  `"siida/config-chain/v1/mainnet"`) set by 006

Each signer signs the 32-byte hash + tag concatenation. The
verifier hashes the payload once and reuses the same input for
`batchVerify`'s message field.

**Rationale**:

- **Hash-then-sign** is the standard pattern for signing large
  payloads. ML-DSA-65 accepts arbitrary-length input but having a
  fixed 32-byte signed message simplifies the verifier and pins
  the canonicality of "what was signed."
- **Domain-separation tag** prevents a signature from one chain
  (e.g., mainnet) being replayed onto another (e.g., testnet).
- **Tag included in the signed message** (not the hash input)
  means the tag does not need to be part of payload_bytes — it's
  scoped to the chain that the verifier knows.

**Alternatives considered**:

- **Sign payload_bytes directly**: requires verifier to receive
  EXACTLY the same payload bytes (no normalisation) which is
  fragile across encoding boundaries.
- **HMAC instead of hash**: HMAC requires a key; here we have
  no shared secret, so plain SHA3-256 is appropriate.

## R3. Signer-index encoding

**Decision**: 16-bit unsigned big-endian integer per signer.
Allows rosters up to 65,535 signers — well beyond any realistic
governance party count.

**Rationale**: 8-bit would cap at 256 signers which is plausibly
limiting for large-scale rosters. 16-bit is the smallest
power-of-two width that's clearly future-safe.

## R4. Duplicate-signer policy

**Decision**: Reject entry with `DuplicateSigner` if any
signer_index appears twice in the signature list. Distinct
signers are required.

**Rationale**: The same signer providing two signatures on the
same payload is either an authoring bug, a tampering attempt, or
a deliberate stuffing of the count. None of those are legitimate;
reject and let the operator investigate.

**Alternative considered**: count the signer once and accept the
entry. Rejected because it hides the anomaly — better to fail
loudly.

## R5. Wire format

**Decision**:

```
offset  size       field
0       1          version tag (0x01)
1       2          signature count n (uint16 big-endian)
3       n × 3296   signatures: each = (2-byte signer_index + 3294-byte PqSignature)
3+n×3296 32        SHA3-256(payload_bytes) — included for verifier convenience
                   (verifiers MUST recompute and compare, not trust this field)
3+n×3296+32 *      payload_bytes (opaque to 014; 006 defines structure)
```

Total fixed overhead: `1 + 2 + n × 3296 + 32 + |payload| = 35 + 3296n + |payload|`.

For n=8: `35 + 26,368 + |payload| ≈ 26.4 KB + payload`.

**Why the hash field is included even though verifiers recompute**:
- saves the verifier one SHA3-256 invocation when it just wants
  to find the signed-message and doesn't need the full payload
  (e.g., when streaming entries through a pipeline)
- canonical placement makes the format easy to parse — the hash
  is at a known offset
- a tampered hash field is caught by recomputation; including it
  doesn't weaken security

**Alternative considered**: omit the hash field, force verifiers
to always recompute. Smaller wire format but less convenient.
Decided convenience wins given the small absolute overhead (32
bytes against a ~26 KB entry).

## R6. Threshold-not-met error verbosity

**Decision**: `ThresholdNotMet` includes both the actual valid count
and the required threshold. This lets operators / audit logs see
how close an entry came to acceptance without revealing which
specific signatures were invalid.

```scala
case ThresholdNotMet(validCount: Int, required: Int)
```

The set of which signers contributed valid sigs is NOT in the
error type — that's a side channel about signer behaviour. If
operators need that breakdown, they can re-verify with a debug
flag (out of scope for 014).

## R7. Library — no new dependency

`PqSignature.batchVerify` from 013 does all the cryptographic
heavy lifting. 014's code is pure Scala: hash + slice + sort +
threshold counting. No Bouncy Castle direct usage.

This is the simplest of the three PQ-migration specs because the
crypto is already done; 014 is essentially a wire-format and
semantics spec.

## R8. Test vector strategy

**Decision**: same as 012/013 (fixed-seed harness, self-referential
KAT). One committed `multi_signed_entry_kat.json` with:

- A 5-member roster (seeds)
- A 32-byte payload
- A 3-of-5 valid entry (signed by members [0, 2, 4])
- Expected wire bytes for the entry
- Expected `VerifyResult.Valid` when verified

Plus negative-case fixtures for each VerifyResult variant.

## R9. Hybrid considerations — explicitly rejected

Per 013 R4: signature hybrids don't add value over PQ-only. The
config chain ships ML-DSA-only.

The classical-era BLS-aggregate config chain (if Siida had shipped
one at all under v1.0.0) would have been a separate format. Since
no chain ships under v1.0.0, there is no migration shim to
maintain.

## R10. Open questions deferred to 006 (config-chain-governance)

- Concrete payload encoding (CBOR / protobuf / custom)
- Replay protection (sequence numbers, epoch boundaries)
- Genesis-entry bootstrap (single-signer trust anchor)
- Roster epoch transitions (entries that change the roster itself)
- Network distribution of chain entries
- Consensus on which entry is "current" when there's a fork
- Threshold M selection per chain instance

All of these are 006's job. 014's contribution is the
per-entry cryptographic verifier and wire format.
