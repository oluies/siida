# modules/crypto

Pairing-based cryptography and primitives used by Siida's PKG and
mixnet layers (Identity-Based Encryption, BLS signatures, BN-254 curve
operations).

This module is a **placeholder** until spec
[`002-crypto-pairing`](../../specs/002-crypto-pairing/spec.md) lands.
That spec decides between gnark-crypto-over-JNI and a pure-Scala BN254
implementation, and ports the `ibe` and `bls` packages from the
Vuvuzela `crypto` repository.

Do not edit the `Placeholder` here in unrelated PRs.
