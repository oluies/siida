# modules/crypto

Pairing-based cryptography for Siida's PKG, mixnet, and config-chain
layers. Provides Identity-Based Encryption (Boneh-Franklin IBE),
BLS signatures with aggregation and proofs-of-possession, and the
underlying BN254 pairing primitives.

This module is being filled by spec
[`002-crypto-pairing`](../../specs/002-crypto-pairing/spec.md);
the public Scala API surface that downstream modules can lock onto
is documented at
[`specs/002-crypto-pairing/contracts/scala-api.md`](../../specs/002-crypto-pairing/contracts/scala-api.md).
See [`quickstart.md`](../../specs/002-crypto-pairing/quickstart.md)
for usage examples.

**Implementation strategy** (resolved in
[`specs/002-crypto-pairing/research.md`](../../specs/002-crypto-pairing/research.md)
R1): gnark-crypto reached over a thin JNI shim, with pre-built
per-architecture native binaries shipped under `native/<triple>/`.
JVM-side bindings use JNA (Apache-2.0).

**Do not edit** the placeholder `Placeholder` here once the spec
lands; the module will be populated by 002's implementation tasks.
