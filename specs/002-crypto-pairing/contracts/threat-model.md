# Contract: Threat-model notes for `modules/crypto`

**Feature**: [spec.md](../spec.md) · **Constitution**: Security & Threat Model section

This is not a re-derivation of the project-level threat model; it's
the *crypto-module-specific* commitments and known non-goals, written
to give the PKG (005), config-chain (006), and SDK (007) specs a
single place to point when describing what they inherit.

## Adversary model in scope

The crypto module is in the *trusted JVM core*. The adversary model
that applies here is the project-level one (global passive adversary
+ minority of compromised mixers / PKGs), restricted to what the
crypto primitives must defend against:

- **IBE**: an adversary holding the master public key and a chosen
  set of (identity, decryption-key) pairs MUST NOT be able to decrypt
  ciphertexts encrypted to any *other* identity. (Standard
  Boneh-Franklin IBE security claim under the BDH assumption.)
- **BLS sign**: an adversary holding a set of (message, signature)
  pairs for public key `pk` MUST NOT be able to forge a signature on
  a *new* message under `pk`. (EUF-CMA security under co-CDH.)
- **BLS aggregate**: an adversary who controls some of the signers
  in an aggregate MUST NOT be able to forge an aggregate signature
  binding an honest signer to a message the honest signer did not
  sign. (Rogue-key resistance via proofs of possession, R6.)

## Constant-time commitments

| Operation                                | Constant-time? | Justification |
|------------------------------------------|----------------|---------------|
| BN254 G1/G2 scalar multiplication        | **Yes**        | gnark-crypto documented constant-time |
| BN254 pairing                            | **Yes**        | gnark-crypto documented constant-time |
| BN254 hash-to-curve (SSWU)               | **Yes**        | SSWU is constant-time; we use IETF map |
| IBE `decrypt` (XOR + HKDF)               | Acceptable     | XOR and HKDF are intrinsically constant-time for fixed-size inputs |
| IBE identity-tag check                   | Acceptable     | Tag is public; comparison is over public data |
| BLS `verify` / `verifyAggregate`         | N/A            | Operates only on public inputs |
| BLS `sign`                               | **Yes**        | Reduces to scalar-mul through the FFI |
| Serialise / deserialise                  | **Yes**        | Byte-level operations on fixed-size buffers |

The Scala layer DOES NOT attempt to make Scala code constant-time;
this is futile under the JIT. Secret-touching code paths are pushed
into gnark-crypto via the FFI. The Scala layer's job is to (a)
marshal bytes in and out, and (b) branch only on public data.

## Known non-goals (out of scope for 002)

- **Side-channel resistance beyond constant-time**: power-analysis
  defences, cache-timing defences, EM-emission defences. The mixnet
  node is a JVM process on commodity hardware; these are not in the
  threat model.
- **Post-quantum security**: BN254 is broken by a sufficiently
  large quantum computer. Migrating to PQC primitives is a future
  spec, not 002.
- **Subgroup confinement attacks during deserialisation**: addressed
  by mandatory subgroup checks on every deserialise (`data-model.md`),
  but a malicious *serialiser* (i.e., the source of a wire-format
  point) is assumed to be no more capable than the project-level
  adversary.
- **Denial of service via expensive operations**: a caller can
  request many pairings; the crypto module does not rate-limit. Rate
  limiting belongs at the ingress boundary.
- **Memory zeroisation after use**: `MasterKey.secret` and
  `BLSPrivateKey.secret` are normal JVM byte arrays. Aggressive
  zeroisation is not attempted in 002 (the JVM heap is the wrong
  level to defend; the PKG and SDK specs may revisit at process
  level).

## Cryptographic-agility hooks

- The KDF in IBE is domain-separated via a versioned tag
  (`"siida/ibe/v1/kdf"`). Bumping to v2 is a follow-up spec.
- The hash-to-curve domain-separation tag is per-usage; the crypto
  module exposes no global tag, only per-call DSTs (IBE uses
  `"SIIDA-BN254-G2-SSWU-RO-IBE"`, BLS uses `"-BLS"`, PoP uses
  `"-POP"`). New consumers add a new suffix; collisions are caught
  by code review.
- The pairing curve (BN254) is wired through the build (native
  binaries, gnark-crypto pin). Swapping to BLS12-381 in a future
  spec is a build-level change, not an API change, because the
  Scala API types are opaque.
