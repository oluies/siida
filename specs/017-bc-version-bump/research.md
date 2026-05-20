# Phase 0 Research: BC Version Bump

**Feature**: [spec.md](./spec.md)
**Date**: 2026-05-20
**Status**: Complete

## R1. Available BC versions

From `repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/maven-metadata.xml`
(fetched 2026-05-20):

| Version | Release date | Notes |
|---|---|---|
| 1.78.1 | 2024-04 | **Currently pinned**. Pre-FIPS 203/204. |
| 1.79   | 2024-mid | First version tracking FIPS 203/204 drafts. |
| 1.80   | 2024-late | Refinements. |
| 1.80.2 | 2025-Q1 | Bugfix release. |
| 1.81   | 2025-mid | |
| 1.81.1 | 2025-mid | Bugfix release. |
| 1.82   | 2025-late | |
| 1.83   | 2026-Q1 | |
| **1.84** | **2026-05** | **Latest stable. Recommended target.** |

The cadence is roughly 1 release per 4–6 months — typical for
BC. Each release picks up active NIST drafts, CVE fixes, and
algorithm additions.

## R2. Why 1.84 (latest)

Choice between "latest" and "first to support FIPS 203/204"
(probably 1.79). Tradeoffs:

| Option | Pro | Con |
|---|---|---|
| Latest (1.84) | Picks up every CVE fix and algorithm refinement since 1.78.1; lowest "next-bump-distance" so Scala Steward proposals will be small | More changes to absorb in one bump |
| First-known-conformant (1.79) | Minimal version delta from current pin | Leaves 5 minor versions of CVE fixes / refinements on the table; Steward would propose 1.84 next anyway |

**Decision**: target 1.84. The 016 audit catches any regression,
so the bigger version jump's risk is contained. The bump PR is
small (one version literal + two baseline updates), and
batching brings us to the head of the release line so future
Steward bumps are minimal.

## R3. Expected BC API surface delta (1.78.1 → 1.84)

BC's policy: PQ public API has been stable since 1.78 introduced
production-ready Kyber and Dilithium classes. The class names
remain `KyberKeyPairGenerator`, `KyberKEMGenerator`,
`KyberKEMExtractor`, `DilithiumKeyPairGenerator`,
`DilithiumSigner` (BC retains the legacy names even after FIPS
203 / 204 finalised the "ML-KEM" / "ML-DSA" terminology).

What may have changed in 1.79+ vs 1.78.1:

- **`DilithiumSigner` may have gained a `ctx` parameter**.
  Likely via `init(...ParametersWithContext(...))` or an
  overloaded `generateSignature(message, ctx)`. If so, the 016
  audit suite needs a small update to pass ctx; the ML-DSA
  sigGen baseline can then realistically flip to 15/15.
- **`DilithiumSigner` may have gained a `deterministic` flag**.
  FIPS 204 distinguishes deterministic (rnd=0^32) vs hedged
  (rnd from secure random) signing. The pinned 1.78.1 has no
  such flag.
- **Class names**: BC sometimes adds `MLKEMKeyPairGenerator` /
  `MLDSAKeyPairGenerator` parallel classes for the
  FIPS-conformant variant while keeping `Kyber*` / `Dilithium*`
  for backwards compatibility. The bump may want to switch to
  the new class names if available.

The exact API delta is determined empirically by running the
bump PR's CI — there's no point pre-speculating beyond a few
likely shapes.

## R4. License integrity check

BC `bcprov-jdk18on:1.78.1` is licensed MIT (Bouncy Castle
Project). Spot-checking BC's announcements and release notes:

- BC 1.79 through 1.84 retain the MIT licence — no change.
- The `NOTICE` attribution we have ("Bouncy Castle Project,
  MIT") remains correct.
- No new transitive dependencies added in BC core (the
  `bcprov-jdk18on` artefact has been zero-deps for years).

## R5. Audit baseline updates

After the bump, the 016 audit suite's baseline constants get
updated. Possible scenarios:

### Scenario A: Full conformance (best case)

| Test | Before | After |
|---|---|---|
| ML-KEM-768 keyGen | 0/25 | 25/25 |
| ML-KEM-768 encap | 25/25 | 25/25 |
| ML-KEM-768 decap | 25/25 | 25/25 |
| ML-DSA-65 keyGen | 0/25 | 25/25 |
| ML-DSA-65 sigGen | 0/15 | 15/15 |

The conformance gap is fully closed. Specs 012 / 013 / 015 can
claim FIPS 203 / 204 byte-for-byte conformance.

### Scenario B: Partial conformance

E.g., ML-KEM closes fully, but ML-DSA still fails sigGen because
BC's `DilithiumSigner` either still lacks ctx or has a different
ctx encoding. The audit baseline updates to reflect the partial
state. A follow-up spec
(e.g., 018-ml-dsa-ctx-wrapper) wraps BC with a small Scala
layer that prepends the FIPS 204 ctx-prefix manually before
signing — a ~50-line workaround.

### Scenario C: No improvement

If even BC 1.84 still ships Round-3, the audit is unchanged and
the bump fails its own success criteria. This escalates to a
provider switch (liboqs, AWS-LC, CIRCL — see 016's research R6).
Unlikely given BC's release-notes track record but not
impossible.

## R6. Constitution alignment

- **Principle I (Metadata Privacy)** — unaffected; BC is the
  primitive provider, not a metadata channel.
- **Principle II (Spec-Driven)** — 017 is the next available
  number; respects the workflow.
- **Principle III (Licence Integrity)** — BC remains MIT;
  `NOTICE` re-verified.
- **Principle IV (Test-First with Deterministic Rounds)** —
  the 016 audit suite IS the test, written before this bump.
- **Principle V (JVM-Native Mixnet Core)** — BC is pure-Java;
  no JNI; no per-arch matrix.

## R7. Scala Steward interaction

`.scala-steward.conf` pins BC at minor-version granularity to
avoid unsupervised bumps:

```
updates.pin = [
  { groupId = "org.bouncycastle", artifactId = "bcprov-jdk18on",
    version = { prefix = "1." } }
]
```

After 017 lands at 1.84, Steward will propose 1.85 (when
released). The 016 audit catches any conformance regression
automatically. Steward's behaviour does not need adjustment.

## R8. What 017 explicitly does NOT do

- Does NOT switch providers (liboqs, AWS-LC, etc.).
- Does NOT migrate to `bcfips-jdk18on` (no PQ support yet).
- Does NOT touch 013 / 015 implementation plans — those happen
  after the bump lands.
- Does NOT add new public APIs to `siida.crypto.api.*`.
- Does NOT certify FIPS 140-3 module validation.
- Does NOT fetch additional NIST ACVP vectors — the 016
  vector set (90 cases) is sufficient for the bump's
  verification.

## R9. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| BC 1.84 still ships Round-3 (no improvement) | Low | Audit detects; spec triggers US2 escalation path |
| BC API breaking changes 1.78.1 → 1.84 | Low–medium | Minimal source updates in-scope per FR-002; if changes are large, bump PR may grow modestly |
| New CVE surfaces only in 1.84 | Very low | BC has good CVE hygiene; would be in release notes |
| Tests run slower with newer BC | Negligible | Audit completes in <1s on darwin-arm64; some slowdown acceptable |
| bcfips becomes viable mid-PR | Negligible | bcfips PQ release is months away per their public timeline; not a near-term concern |
