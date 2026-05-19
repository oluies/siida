# Notes — KAT vectors deferred (T019, T020, T021, T022, T030)

**Status**: 002's IBE, BLS, and BN254-primitive code is complete and
covered by deterministic round-trip + bilinearity + cross-key
rejection tests on `darwin-arm64` and `linux-amd64`. External KAT
vectors against a non-self-referential reference are deferred to a
follow-up PR.

## Why

The original task plan (T019–T022 for US1, T030 for US3) called for
JSON KAT files derived from:

- gnark-crypto's BN254 primitive tests (committed via Go program)
- IETF `draft-irtf-cfrg-hash-to-curve` appendix vectors
- A fixed-seed Scala harness producing IBE / BLS KATs

In practice, only the third source is fully reachable from the
current build:

1. **gnark-crypto Go test data** is structured Go test code, not
   serialisable vector files. Extracting it requires a small Go
   program in `modules/crypto/native/` that prints the test inputs +
   expected outputs as JSON. That program itself becomes a tracked
   artefact requiring its own review.

2. **IETF draft-irtf-cfrg-hash-to-curve-16** does NOT include BN254
   in its appendix as of 2026-05-19. The drafts that did mention BN
   curves used a different curve form (the dclxvi BN256, not the
   gnark-crypto BN254 a.k.a. alt_bn128).

3. **Fixed-seed Scala harness** is self-referential: the KAT is
   produced by the same code path we're trying to validate. It
   catches regressions but not first-introduction bugs.

The current test suites give us all the regression protection a
self-referential KAT would provide, plus bilinearity, PoP cross-key
rejection, and serialisation round-trip checks. The marginal value of
self-referential KATs is low; the marginal value of properly external
KATs is high but blocked on the work above.

## What lands when the KAT PR happens

- `modules/crypto/native/extract_kats/` — a small Go program that
  reads gnark-crypto's exported test fixtures and writes JSON.
- `modules/crypto/test/resources/{bn254,bls}_vectors.json` —
  externally-sourced KATs (gnark-crypto primitive tests + Ethereum
  precompile vectors).
- `modules/crypto/test/resources/ibe_vectors.json` —
  self-referential, but documented as such and produced by a tracked
  generator script that anyone can re-run.
- `BN254VectorsSuite.scala`, `HashToCurveSuite.scala` —
  KAT-comparison suites that consume the JSON files.

## Tasks marked as deferred (rather than done)

| Task | Status | Reason |
|------|--------|--------|
| T019 (sswu_vectors.json from IETF) | deferred | BN254 not in draft-irtf-cfrg-hash-to-curve-16 |
| T020 (bn254_vectors.json from gnark) | deferred | needs Go extraction program |
| T021 (ibe_vectors.json self-generated) | deferred (low priority) | regression protection already in IBESuite |
| T022 (HashToCurveSuite) | deferred | depends on T019 |
| T030 (BN254VectorsSuite) | deferred | depends on T020 |

When the KAT PR lands, this note can be removed.
