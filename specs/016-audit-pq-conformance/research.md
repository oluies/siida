# Phase 0 Research: PQ Conformance Audit

**Feature**: [spec.md](./spec.md)
**Date**: 2026-05-20
**Status**: Complete

## R1. Why BC 1.78.1 is suspect

| Date         | Event |
|--------------|-------|
| 2024-04      | Bouncy Castle 1.78.1 released. Includes Kyber768 (NIST Round 3) and Dilithium3 (Round 3) implementations. |
| 2024-08-13   | NIST publishes FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) as final standards. |
| 2024-Q4 –    | Subsequent BC releases (1.79, 1.80) progressively update the implementations to match the finalised standards. |
| 2026-05-20   | Spec 012 (using BC 1.78.1) is on Siida's main; spec 013 mandates BC for ML-DSA-65 too. |

The 4-month gap between BC 1.78.1's release and FIPS finalisation
means BC 1.78.1's "Kyber768" and "Dilithium3" are the **submission
versions**, not the finalised FIPS standards. The differences are
documented (next section) and minor but byte-relevant.

## R2. Known FIPS 203 / 204 finalisation tweaks vs Round 3

### ML-KEM (Kyber → FIPS 203)

From FIPS 203 §1.4 (changes from Round 3 submission):

1. **Domain separation byte** in `K-PKE.Encrypt`: the byte `0x01`
   was added at a specific position in the SHA3-512 input to
   distinguish the encryption path from the key generation path.
   Round-3 Kyber did not have this byte.
2. **G() and J() hash invocations**: small ordering changes in
   what's hashed for derivation of `K_bar`.
3. **Rejection sampling for `t1` packing**: a subtle change in
   how the high-order bits are extracted before serialisation.
4. **Standard input length checks**: FIPS 203 mandates explicit
   length validation on `decapsulate`'s ciphertext input.

Net effect: **byte-for-byte different** ciphertext / shared
secret output for the same (sk, pk, randomness) inputs. A
FIPS-203 implementation cannot decapsulate a Kyber-Round-3
ciphertext (the K_bar derivation differs).

### ML-DSA (Dilithium → FIPS 204)

From FIPS 204 §1.4:

1. **ExpandMask**: minor tightening of the rejection sampling
   when expanding the masking polynomial from the secret seed.
2. **Hint encoding**: the `h` (hint) vector serialisation changed
   to a more compact format.
3. **Domain separators**: like ML-KEM, additional fixed bytes were
   added to certain SHAKE invocations.

Net effect: same as above — byte-for-byte different signatures.

## R3. NIST ACVP test vector availability

NIST publishes "Algorithm Validation Program" (ACVP) test
vectors at <https://github.com/usnistgov/ACVP-Server>. The
relevant directories:

- `gen-val/json-files/ML-KEM-keyGen-FIPS203/`
- `gen-val/json-files/ML-KEM-encapDecap-FIPS203/`
- `gen-val/json-files/ML-DSA-keyGen-FIPS204/`
- `gen-val/json-files/ML-DSA-sigGen-FIPS204/`
- `gen-val/json-files/ML-DSA-sigVer-FIPS204/`

Each vector set has hundreds of test cases. The audit's test
suites parse the JSON, run BC's implementation, and assert
byte-for-byte equality.

Vectors are licensed CC0 (NIST public-domain release), so
committing them into `modules/crypto/test/resources/` is
licence-compatible per constitution Principle III.

## R4. BC 1.79+ status — likely fixes the gap

Based on BC's release notes pattern (each minor release picks up
NIST standardisation drafts), BC 1.79 (released ~mid-2024) and
later should track FIPS 203 / 204 finalisation. The audit's
test suite catches this either way: if BC 1.78.1 passes, no
action; if it fails and BC 1.79+ passes when bumped, the
remediation is a focused dependency bump.

## R5. bcfips-jdk18on status — currently incomplete for PQ

`org.bouncycastle:bcfips-jdk18on` is BC's FIPS 140-3 validated
edition. Its release cadence is slower than the general-purpose
provider because each release requires CMVP re-validation.

As of 2026-05, the `bcfips` provider's PQ support status (based
on BC documentation):

- **ML-KEM and ML-DSA in bcfips**: planned but not yet shipped
  in a validated release. The general-purpose `bcprov` is the
  only viable BC artefact for PQ today.
- **FIPS 140-3 validation timeline**: typically 6-18 months
  from upstream code freeze to CMVP certificate. We track this
  but don't depend on it.

If a future Siida deployment requires FIPS 140-3 compliance
(e.g., for European government procurement under specific
regulatory frameworks), the audit's remediation list MUST flag
this. For now, `bcprov` is the right choice.

## R6. Alternative providers

| Provider | Status | Pros | Cons |
|---|---|---|---|
| **BC bcprov** (current) | Pure-Java, MIT | Already in use; no JNI; covers all schemes Siida needs | Not FIPS 140-3 validated; Kyber Round-3 in 1.78.1 |
| **BC bcfips** | Pure-Java, FIPS-validated, separate licence | FIPS 140-3 compliance | No PQ support yet (as of 2026-05) |
| **liboqs** via JNI | C library, Apache 2.0 | Comprehensive PQ scheme support; tracks NIST early | Re-introduces 002's per-arch matrix complexity; non-FIPS |
| **AWS-LC** via JNI | C library, ISC | FIPS 140-3 validated, includes PQ | Non-trivial JNI footprint; vendor-bias |
| **Cloudflare CIRCL** | Go library | Active development; clean code | Requires JNI from JVM; non-FIPS |

The audit's purpose is not to switch providers; it's to
characterise the gap (if any) with the current BC choice. Switch
decisions are downstream specs informed by the audit's findings.

## R7. Test vector strategy

The audit suites consume NIST ACVP vectors directly (no
fixed-seed self-referential generation like 012/013/015 use).
ACVP vectors are public, signed by NIST, and updated as the
standards evolve — they're the canonical conformance source.

We commit the relevant subset (parameter set 3 for both ML-KEM
and ML-DSA) into the test resources. Bulk size: ~10 MB of JSON
for the full ACVP set per algorithm; we may down-select to a
smaller representative set if the full corpus is unwieldy.

## R8. What the audit does NOT do

- **Does NOT implement a remediation.** If BC 1.78.1 fails the
  audit, the report recommends a bump-or-switch; the actual
  follow-up code change is a separate spec (e.g.,
  017-bc-version-bump or 018-switch-pq-provider).
- **Does NOT cover other PQ primitives.** Only ML-KEM-768 and
  ML-DSA-65 as used by 012 / 013. If future specs add SLH-DSA
  or Falcon, separate audit specs cover those.
- **Does NOT validate FIPS 140-3 (module-level)**. Algorithm
  conformance and module validation are distinct; this spec
  covers only the former.
- **Does NOT certify Siida as FIPS-compliant.** That requires
  bcfips + CMVP-validated build + auditor walkthrough — a
  multi-spec effort if ever needed.

## R9. Open questions deferred to follow-up specs

- **If audit fails**: which specific BC version restores
  conformance? (Determined by trial; remediation spec captures
  the bump.)
- **If audit passes**: cadence — should we re-audit on every
  BC version bump triggered by Scala Steward? Probably yes;
  recommend folding into 003's Steward workflow as a required
  check on BC bumps.
- **bcfips migration**: triage when ML-KEM/ML-DSA ship in a
  validated bcfips release. Separate spec.
- **Vector source canonicality**: if NIST stops publishing
  ACVP JSON in the expected format, fallback to vectors from
  the FIPS 203 / 204 standard documents directly.
