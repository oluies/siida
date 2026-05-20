# Phase 0 Research: PQ BLS Replacement (ML-DSA-65)

**Feature**: [spec.md](./spec.md)
**Date**: 2026-05-20
**Status**: Complete

## R1. Signature scheme — ML-DSA-65 (FIPS 204)

**Decision**: ML-DSA-65 (FIPS 204, parameter set 3, formerly
Dilithium-65).

**Rationale**: BSI TR-02102-1's recommended PQ signature scheme.
NIST FIPS 204 standardisation completed 2024-08. Parameter set 3
targets ~128-bit classical-equivalent security with public-key
size 1952 bytes and signature size 3293 bytes. Same security
level as ML-KEM-768 we chose for 012's KEM — consistent across
the migration.

Swedish provenance: lattice analysis at Lund (Thomas Johansson)
covered Dilithium's underlying problems (Module-LWE / Module-SIS)
pre-standardisation. Not a direct design contribution but
documented review-lineage.

**Alternatives considered**:

- **ML-DSA-87 (parameter set 5)**: ~192-bit security, ~50% larger
  signatures (4595 bytes). Reserve for a future high-assurance
  spec.
- **SLH-DSA (FIPS 205, formerly SPHINCS+)**: hash-based, conservative
  security assumption (no lattice problem). Signature sizes
  17 KB–50 KB depending on parameter set. Slow to sign. Defer to
  a future archival-signature spec where size is acceptable.
- **Falcon (FN-DSA, FIPS 206 draft)**: smaller signatures than
  ML-DSA but harder to implement constant-time (uses
  floating-point arithmetic). BC's implementation status as of
  2026 is less mature.

## R2. The aggregation gap

BLS signatures aggregate via G2-point sum. ML-DSA does not. The
lattice structure that gives ML-DSA its security also blocks the
homomorphism BLS exploits. Per 011 research R3:

> **No PQ aggregate signature** is production-grade. Substitute:
> batch verification of individual ML-DSA signatures, OR
> multi-signature SQIsign variant (research).

013 implements the "batch verification" half. The "lose
aggregation" semantic is a hard fact, surfaced explicitly in
the API rather than emulated.

For the config-chain use case (which DID rely on BLS aggregation
in the original Vuvuzela design), spec 014 redesigns the chain
around batched per-signer ML-DSA signatures.

## R3. Batch verification construction

**Decision**: Bouncy Castle's ML-DSA implementation does NOT
include a native `batchVerify` API as of 1.78.1. Implement
batching at the Scala layer using the standard shared-random
coefficient construction:

```
Verify in batch: ∀ i, accept iff ∑_i c_i · L_i(pk_i, msg_i, sig_i) == ∑_i c_i · R_i(pk_i, msg_i, sig_i)
                 where c_i are fresh random coefficients in Z_q
                 and L_i / R_i are the per-signature lattice expressions
                 normally compared individually
```

Per Pino-Vidaud's *Efficient and Provable Multi-Signatures for ML-DSA*
(2024), the batched check has ~0.6n verification work for n in [8, 32].

**Alternative considered**: just run `verify` in a loop. Simpler
but no CPU saving. Provided as a fallback; the batch API call
sites can opt into either.

**Pragmatic note**: BC may add native ML-DSA batch verify in a
future release. When that happens, swap our Scala-layer batch
implementation for the BC native and bump the BC version. Until
then the Scala layer is what we ship.

## R4. Hybrid signatures — explicitly rejected

The KEM-hybrid pattern (012) combines two shared secrets via a
hash combiner so an adversary breaking only one half still
sees random AEAD keys. **This does not transfer to signatures**
because signatures are verified, not decrypted:

- A hybrid signature `(sigBLS, sigMLDSA)` is verified iff BOTH
  verify
- An adversary who breaks ONE of the two halves can forge that
  half; the hybrid sig is `(forged_BLS, valid_MLDSA)` — verify
  succeeds iff both succeed, so the attacker needs both
- This gives `max(classical, PQ)` security: as soon as ONE is
  broken, the hybrid is broken
- Worse: verifier cost is 2× and signature size is `sig_BLS +
  sig_MLDSA`

BSI / ENISA / IETF guidance on PQ signatures all agree: ship PQ-
only signatures, plan a hard cutover per consumer, accept the
costs. We follow that consensus.

**Alternative considered**: concurrent dual-signature deployment
where verifier accepts EITHER. This is the right shape for a
soft migration but it's NOT a hybrid; it's a downgrade path. Reject
for security reasons — a downgrade-accepting verifier is
quantum-vulnerable until PQ-only enforcement starts.

## R5. Algorithm-ID space for signatures

**Decision**: signatures use algorithm-ID space `0x10–0x1F`,
distinct from 012's onion-layer space (`0x00–0x0F`). This makes
the wire-format byte unambiguous when a single envelope might
carry both (e.g., signed and encrypted messages).

| ID    | Meaning                                          | Status |
|-------|--------------------------------------------------|--------|
| 0x10  | ML-DSA-65 (FIPS 204) — this spec                 | CURRENT |
| 0x11  | Reserved for ML-DSA-87 (high assurance)          | RESERVED |
| 0x12  | Reserved for SLH-DSA (archival)                  | RESERVED |
| 0x13  | Reserved for Falcon (small signatures)           | RESERVED |
| 0x14–0x1F | Reserved                                     | RESERVED |

## R6. Test vector strategy

**Decision**: same as 012. Fixed-seed harness; one KAT vector
committed at `modules/crypto/test/resources/ml_dsa_65_kat.json`.
External NIST CAVS vectors deferred to a follow-up.

## R7. Constant-time guarantees

| Operation              | Constant-time?  | Source |
|------------------------|-----------------|--------|
| ML-DSA-65 keygen       | Yes             | BC documented |
| ML-DSA-65 sign         | Yes             | BC documented |
| ML-DSA-65 verify       | Acceptable      | Verify operates on public inputs |
| `batchVerify` Scala layer | Acceptable   | Coefficients are public; batch math is over public inputs |

## R8. Library choice — Bouncy Castle (same as 012)

**Decision**: `org.bouncycastle:bcprov-jdk18on:1.78.1` (already
in `modules.crypto.ivyDeps` from spec 012). No new dependency
introduced by 013.

BC's API at the `org.bouncycastle.pqc.crypto.crystals.dilithium`
package:
- `DilithiumKeyGenerationParameters`
- `DilithiumKeyPairGenerator`
- `DilithiumParameters.dilithium3` ← ML-DSA-65
- `DilithiumSigner` (sign + verify)
- `DilithiumPublicKeyParameters` / `DilithiumPrivateKeyParameters`

## R9. BLS deprecation discipline

The existing `siida.crypto.api.BLS` object stays compilable and
functional during the migration. We add `@deprecated` annotations
so new code gets a warning; existing tests (002's BLSSuite)
continue to pass.

Deprecation TEXT:
> `BLS over BN254 is quantum-vulnerable per constitution v2.0.0
> Principle I. Use PqSignature for new code; this object will be
> removed in a future spec once all callers have migrated.`

No removal in 013. Removal happens after 014 (config-chain) and
any other BLS consumer has cut over.

## R10. Open questions deferred to later specs

- **Hybrid dual-signature deployment** for soft migration: separate
  spec if needed.
- **Multisig / threshold schemes** for parties that need
  combine-able signatures: separate spec; FROST-equivalent for ML-DSA
  is research-stage as of 2026-05.
- **Falcon / FN-DSA migration**: a future spec when BC's
  implementation matures.
- **External KAT vectors**: deferred follow-up, same as 002 / 012.
