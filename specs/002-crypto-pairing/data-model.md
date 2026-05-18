# Phase 1 Data Model: Crypto Pairing (BN254 + IBE + BLS)

**Feature**: [spec.md](./spec.md) · **Plan**: [plan.md](./plan.md) · **Research**: [research.md](./research.md)

The crypto module is pure computation: it holds **values**, never
persistent or networked state. The entities listed below are
immutable, serialisable, in-memory data carriers exposed by the
public Scala API. Each maps to a fixed-size byte representation that
matches the gnark-crypto compressed encoding (R3); cross-language
audit can compare these byte forms directly.

## Entities

### MasterKey (IBE)

Holds both the master secret (PKG-only) and the master public key
(distributable). Created by `IBE.generateMasterKey`.

- `secret: Scalar` — random `s ∈ Z_r`. NEVER serialised to disk by
  the crypto module; the PKG (005) owns persistence.
- `public: G1Point` — `g1 ^ secret`. Distributed widely.
- Validation: `secret` MUST be in `[1, r-1]`; the zero scalar is
  rejected.

### MasterPublicKey (IBE)

The publishable half of `MasterKey`. Distinct type so APIs that
should never see the secret (encrypt) can be typed against it.

- `public: G1Point`
- Validation: subgroup-check the G1 point on construction.
- Serialised form: 32 bytes (G1 compressed).

### IdentityKey (IBE)

Per-identity decryption key, derived by the PKG.

- `identity: Bytes` — the identity string (e.g., a username; the PKG
  enforces format). Kept alongside the key so accidental
  cross-identity decryption is impossible.
- `key: G2Point` — `H_G2(identity) ^ secret`.
- Validation: subgroup-check the G2 point on construction.
- Serialised form: 64 bytes (G2 compressed) plus length-prefixed
  identity bytes; the identity is part of the cipher-binding (see
  Ciphertext below).

### Ciphertext (IBE)

Output of `IBE.encrypt`.

- `c1: G1Point` — `g1 ^ r` for random `r`.
- `c2: Bytes` — `message ⊕ KDF(e(MPK, H_G2(identity)) ^ r)`.
- `identityTag: Bytes` — first 16 bytes of `SHA-256(identity)`; an
  unauthenticated hint used by `decrypt` to refuse a wrong-identity
  attempt cheaply. NOT a security guarantee — the cryptographic
  protection is the IBE construction itself.
- Validation: `c1` subgroup-checked; `c2.length` MUST equal the
  plaintext length range allowed by the construction; `identityTag`
  MUST be 16 bytes.
- Serialised form: 32 (`c1`) + 16 (`identityTag`) + variable (`c2`).

### BLSPrivateKey

Held only by signers.

- `secret: Scalar` — random `sk ∈ Z_r`.
- Validation: `[1, r-1]`.
- Serialised form: 32 bytes.

### BLSPublicKey

- `point: G1Point` — `g1 ^ secret`.
- Validation: subgroup-check on construction.
- Serialised form: 32 bytes (G1 compressed).

### BLSSignature

- `point: G2Point` — `H_G2(message) ^ secret` for a single sig, or
  the product of multiple individual signatures for an aggregate.
- `kind: SignatureKind` — enum `Single | Aggregate`; informational,
  affects which `verify` overload is expected.
- Validation: subgroup-check.
- Serialised form: 65 bytes (1 byte kind tag + 64 bytes G2
  compressed).

### ProofOfPossession (BLS)

A BLS signature over the signer's own public key, used to defend
against rogue-key attacks during aggregation.

- `pop: BLSSignature` (kind=`Single`) — signed over the public key
  with the BLS PoP domain-separation tag `"SIIDA-BN254-G2-SSWU-RO-POP"`.
- Validation: when verifying aggregates, every contributing public
  key MUST carry a valid PoP that the verifier has already checked.
- Serialised form: 65 bytes (same as `BLSSignature`).

### Scalar (BN254 internal)

- `bytes: Array[Byte]` of length 32, big-endian, reduced mod `r`.
- Validation: in `[0, r-1]`. The constructor reduces on input rather
  than rejecting, so any 32-byte value is a valid scalar; callers
  who want `[1, r-1]` (no zero) ask the API explicitly.

### G1Point (BN254 internal)

- `bytes: Array[Byte]` of length 32 (compressed encoding).
- Validation: must lie on the BN254 G1 curve AND in the prime-order
  subgroup (subgroup-check is mandatory; without it BLS verify is
  unsound).

### G2Point (BN254 internal)

- `bytes: Array[Byte]` of length 64 (compressed encoding).
- Validation: must lie on the BN254 G2 curve AND in the prime-order
  subgroup.

### GTElement (BN254 internal)

- `bytes: Array[Byte]` of length 384.
- Validation: must lie in the GT subgroup (cyclotomic check).
- Typically not surfaced to API consumers; only the BLS verify path
  compares two GT elements internally.

## Relationships

```
MasterKey ────────┐
   ├─ secret      │ generateMasterKey
   └─ public ─────┴──> MasterPublicKey ──┐
                                          │ encrypt(MPK, identity, message)
   issueKey(MK, identity) ──> IdentityKey │
                                          ├──> Ciphertext
   decrypt(IdK, Ciphertext) ──> Either[IBEError, Bytes]
                                          │
                                          └──> recovered plaintext
                                                (must equal original)

BLSPrivateKey ─┐
   ├─ secret   │ generateBLSKeyPair
   └─ public ──┴──> BLSPublicKey
                    │
                    ├──> sign(sk, msg) ──> BLSSignature (Single)
                    ├──> sign(sk, pk_bytes, POP_tag) ──> ProofOfPossession
                    │
                    └──> verify(pk, msg, sig) ──> Boolean
                         aggregate([sig1, ..., sign]) ──> Either[BLSError, BLSSignature(Aggregate)]
                         verifyAggregate([pk1, ..., pkn], [pop1, ..., popn], msg, aggSig)
                            ──> Boolean
```

## State transitions

None of these entities have state in the conventional sense; they are
immutable values. The only "lifecycle" worth naming is the IBE
master-key lifecycle, which is **fully owned by the PKG (005)**:

```
[no master key]
      │ generateMasterKey
      ▼
[active]                      ← issueKey(...) callable any number of times
      │ (PKG rotation; spec 006)
      ▼
[retired]                     ← issueKey(...) MUST refuse; outstanding
                                IdentityKey instances still decrypt
                                ciphertexts produced before retirement
```

The crypto module exposes the primitives; the *state machine* lives
in the PKG (005) and the config-chain (006). Documenting it here so
those specs have an unambiguous handoff.

## Validation summary (consolidated)

| Entity              | On-construction check                                          | Error type           |
|---------------------|----------------------------------------------------------------|----------------------|
| MasterKey           | secret ∈ [1, r-1]; recompute and check `public = g1 ^ secret`  | `IBEError.InvalidKey`|
| MasterPublicKey     | G1 subgroup check                                              | `IBEError.InvalidPoint` |
| IdentityKey         | G2 subgroup check; identity not empty                          | `IBEError.InvalidKey` |
| Ciphertext          | c1 G1 subgroup; identityTag length 16; c2 length in bounds     | `IBEError.MalformedCiphertext` |
| BLSPrivateKey       | scalar ∈ [1, r-1]                                              | `BLSError.InvalidKey` |
| BLSPublicKey        | G1 subgroup                                                    | `BLSError.InvalidPoint` |
| BLSSignature        | G2 subgroup; kind tag valid                                    | `BLSError.InvalidSignature` |
| ProofOfPossession   | BLSSignature checks + verifies against the claimed public key  | `BLSError.InvalidPOP` |
| Scalar (internal)   | reduce mod r (never throws)                                    | —                    |
| G1Point (internal)  | on-curve + subgroup                                            | `BLSError.InvalidPoint`/`IBEError.InvalidPoint` |
| G2Point (internal)  | on-curve + subgroup                                            | same                 |
| GTElement (internal)| cyclotomic subgroup                                            | —                    |
