# Quickstart: Crypto Pairing (BN254 + IBE + BLS)

**Feature**: [spec.md](./spec.md) · **Plan**: [plan.md](./plan.md)

This quickstart shows how a downstream-spec contributor (PKG 005,
configchain 006, SDK 007, agent 008) uses the crypto module. It is
also the validation contract for the spec's success criteria.

## Prerequisites

Same as 001-project-bootstrap:

- JDK 21 LTS
- The `./mill` launcher (or `make`) checked out
- The committed per-arch native binaries under
  `modules/crypto/native/<triple>/` (`linux-amd64`, `linux-arm64`,
  `darwin-amd64`, `darwin-arm64`)

If a contributor is on a *fifth* architecture not in the table, the
JVM fails loudly at the first crypto call. Adding a new arch means
running the native-build matrix job (see `research.md` R4) and
committing the resulting `.so` / `.dylib`.

## Smoke test

From the repo root:

```sh
make test                               # runs all module tests including crypto
./mill modules.crypto.test              # just the crypto module
```

Expected output for the crypto suite: BN254 primitive vectors pass,
IBE round-trip passes, BLS sign/verify/aggregate passes, cross-arch
determinism passes (i.e., the test harness ran on this arch and the
serialised outputs match the committed expected bytes).

## Using IBE from a downstream module

```scala
import siida.crypto.api.{IBE, IBEError, MasterKey, MasterPublicKey, IdentityKey, Ciphertext}
import java.security.SecureRandom

val rng = SecureRandom.getInstance("DRBG")

// PKG side
val mk: MasterKey = IBE.generateMasterKey(rng)
val mpk: MasterPublicKey = IBE.publicKey(mk)

val alice: Array[Byte] = "alice@siida".getBytes
val aliceKey: IdentityKey = IBE.issueKey(mk, alice)

// Sender side (knows only mpk and alice's identity string)
val ct: Ciphertext = IBE.encrypt(mpk, alice, "hello".getBytes, rng)

// Alice side
val plain: Either[IBEError, Array[Byte]] = IBE.decrypt(aliceKey, ct)
// plain == Right("hello".getBytes)

// Trying with a wrong identity key
val bob: Array[Byte] = "bob@siida".getBytes
val bobKey: IdentityKey = IBE.issueKey(mk, bob)
val wrong = IBE.decrypt(bobKey, ct)
// wrong == Left(IBEError.WrongIdentity)
```

Wire-format work (sending the ciphertext to the recipient over the
mixnet) is the SDK's job (007). The crypto module just provides
`serialiseCiphertext` / `deserialiseCiphertext` for that.

## Using BLS from a downstream module

```scala
import siida.crypto.api.{BLS, BLSError, BLSPrivateKey, BLSPublicKey, BLSSignature, ProofOfPossession}
import java.security.SecureRandom

val rng = SecureRandom.getInstance("DRBG")

// Two signers
val (sk1, pk1) = BLS.generateKeyPair(rng)
val (sk2, pk2) = BLS.generateKeyPair(rng)

// Proofs of possession (required for aggregate verification)
val pop1: ProofOfPossession = BLS.proofOfPossession(sk1)
val pop2: ProofOfPossession = BLS.proofOfPossession(sk2)

// Both sign the same message
val msg = "config-chain epoch 42".getBytes
val sig1 = BLS.sign(sk1, msg)
val sig2 = BLS.sign(sk2, msg)

// Verify individually
assert(BLS.verify(pk1, msg, sig1))
assert(BLS.verify(pk2, msg, sig2))

// Aggregate and verify
val agg: BLSSignature = BLS.aggregate(Seq(sig1, sig2)).toOption.get
assert(BLS.verifyAggregate(Seq(pk1, pk2), Seq(pop1, pop2), msg, agg))
```

The config-chain spec (006) will use this pattern for multi-signer
attestations of config updates.

## What "success" looks like

- `./mill modules.crypto.compile` exits with code `0`.
- `./mill modules.crypto.test` reports green for: BN254 KAT vectors,
  IBE round-trip + wrong-identity refusal + KAT, BLS sign/verify +
  aggregate + PoP + KAT, cross-arch determinism.
- `./mill SiidaBuild.millSiidaHeaderCheck` continues to pass — the
  ported BSD-3-clause files are recognised via `ported.json`.

## Troubleshooting

- **`UnsatisfiedLinkError: libsiida_bn254`** on JVM startup → your
  architecture is not in the supported set. Either add it via the
  native-build matrix job or run on a supported developer platform.
- **`IBEError.DecryptionFailed` after a clean round-trip** → almost
  always a serialisation bug in the caller (wrong byte order or
  truncated buffer). Re-run with `serialiseCiphertext` ∘
  `deserialiseCiphertext` as a check.
- **Tests pass locally but fail on CI** → cross-arch determinism
  bug. The crypto module's tests serialise expected outputs and
  diff bytes; the diff in the failure message tells you which byte
  range differs.
- **`make headers` fails on a newly added file under
  `modules/crypto/internal/ported/`** → you forgot to add the path
  to `build/licence-headers/ported.json`. Add it with a short
  `reason` field and re-run.

## Validation checklist (for spec verification)

- [ ] All FR-007 known-answer vectors pass (SC-001).
- [ ] Outputs match byte-for-byte across Linux/amd64 and macOS/arm64
      runs (SC-002).
- [ ] No downstream-module commit edits files under `modules/crypto/`
      after 002 merges (SC-003).
- [ ] One pairing < 50ms, one IBE encrypt < 100ms, one BLS sign < 50ms
      on a typical laptop (SC-004).
- [ ] `make headers` green for `modules/crypto/` (SC-005).
- [ ] Every file in `modules/crypto/` traceable to either AGPL
      header, `ported.json` entry, or `NOTICE` (SC-006).
