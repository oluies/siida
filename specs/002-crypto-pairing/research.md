# Phase 0 Research: Crypto Pairing (BN254 + IBE + BLS)

**Feature**: [spec.md](./spec.md)
**Date**: 2026-05-17
**Status**: Complete — all open questions resolved, including the
load-bearing implementation-strategy decision deferred from `spec.md`
FR-009.

This document resolves the questions left open by `spec.md` and locks
the concrete decisions that `plan.md`, `data-model.md`, `contracts/`,
and `tasks.md` will build on.

---

## R1. Implementation strategy — gnark-crypto JNI vs. pure-Scala BN254

**Decision**: **gnark-crypto reached over a small JNI shim, with
pre-built per-architecture native binaries shipped alongside the JAR.**
The pure-Scala BN254 path is rejected.

**Rationale**:

The decision balances four constitutional constraints against
practical reality:

1. *Cryptographic correctness* (Principle IV, "no flaky tests masking
   regressions in the privacy guarantee"). gnark-crypto's BN254
   implementation is battle-tested in production zkSNARK rollups and
   in Ethereum precompiles; it has formal-style test vectors,
   constant-time arithmetic on the field operations that need it,
   and continuous fuzz-testing upstream. A from-scratch pure-Scala
   BN254 is a multi-month implementation+audit effort that does not
   make Siida better at metadata privacy (its actual differentiator)
   and that, if subtly wrong, would silently break IBE and BLS in
   ways no smoke test would catch.

2. *Licence integrity* (Principle III). gnark-crypto is Apache-2.0;
   the JNI shim is AGPL-3.0-or-later authored locally. Both are
   compatible with the Siida AGPL umbrella. The header allowlist
   (`build/licence-headers/ported.json`) covers any source files we
   port from `github.com/vuvuzela/crypto` (BSD-3-clause); native
   binaries don't go through the header check (they're not source).

3. *Build portability* (Principle V, "build and produce identical
   artefacts on every architecture Pekko supports"). The
   constitution explicitly anticipates the JNI case:
   > Native code reached over JNI (e.g., gnark-crypto) MUST ship
   > pre-built binaries or build hermetically for every supported
   > architecture; otherwise a pure-Scala fallback MUST exist.
   We choose pre-built binaries. The four target triples are
   `darwin-arm64`, `linux-amd64`, plus `linux-arm64` and
   `darwin-amd64` for completeness. Pre-built binaries are produced
   by a GitHub Actions matrix job (one runner per arch) and
   committed under `modules/crypto/native/<arch>/`. Each is
   loaded at JVM startup by JNA, extracted from the JAR to a
   tmp dir, and System.load()ed. Contributors install nothing
   beyond JDK 21.

4. *Speed of delivery* (the constitution does not state this
   constraint explicitly but the project is pre-alpha and the
   roadmap has eight more features after 002). Pure-Scala BN254
   would push 004 (mixnet) back by months. JNI to a known-good
   primitive lets us move now.

**Alternatives considered and why rejected**:

- **Pure-Scala BN254 from scratch.** Implementation + audit risk
  for no privacy-relevant gain. A "Scala implementation of BN254"
  is not a feature Siida users will notice; a *correct* mixnet
  on top of a *correct* primitive is. Deferred as a possible
  future feature if a serious cryptographer joins the project.
- **Apache Milagro / AMCL Java pairing library.** Pure-Java,
  Apache-2.0, used by Hyperledger. Two practical concerns: (a)
  AMCL's BN curve support has historically been weaker than its
  BLS12-381 support, and (b) the project's Apache Incubator status
  has churned. Reconsider in a future spec if a stable pure-JVM
  BN254 path matures.
- **Web3j / BouncyCastle BN254.** Web3j's BN254 is a port of an
  earlier OpenZeppelin implementation; not the right level of
  audit attention for a research mixnet. BouncyCastle's pairing
  support is incomplete for BN254 as of the version we'd be
  pulling.
- **Herumi `mcl` via JNI.** Performant, MIT-licensed, has Java
  bindings. Rejected because it has a smaller user base than
  gnark-crypto in 2026 and gnark-crypto's test vectors are what
  the wider Ethereum / zkSNARK ecosystem standardises on.
- **Calling gnark-crypto via a Go-binary subprocess** (no JNI).
  Per-call latency would be milliseconds even for cheap ops;
  unworkable for any production traffic and overkill for the
  small primitive surface we need.

---

## R2. JVM-native foreign-function mechanism

**Decision**: **JNA (Java Native Access) v5.x**, with `net.java.dev.jna:jna`
declared as a dependency, licence chosen as Apache-2.0 (JNA is
dual-licensed Apache-2.0 / LGPL-2.1; we pick Apache to keep the
licence chain uniformly Apache-compatible).

**Rationale**: JNA is the boring, mature, stable choice. It works on
every JVM Siida supports, requires no `--enable-preview` flags, and
its overhead (~100ns per call) is dwarfed by the cost of a BN254
pairing (~ms). Maintenance burden is near zero; the JNA wrapper for
our ~12 primitive C functions is a few dozen lines.

**Alternatives considered**:

- **Project Panama FFM (JEP 442).** Finalised in JDK 22. In JDK 21
  it is incubator status (`--enable-preview` + `--add-modules
  jdk.incubator.foreign`). Cleaner API surface, faster (no
  reflective dispatch), and the future of JVM FFI. Rejected for
  002 because preview-flag dependence makes the bootstrap fragile
  while the constitution pins JDK 21. Revisit in a future spec
  once the JDK pin moves to 22+.
- **Raw JNI (hand-written C glue + `javah`).** More verbose, more
  error-prone, no functional advantage over JNA for our use case.
- **jnr-ffi.** Roughly equivalent to JNA. JNA has wider Maven
  Central traction and longer history.

---

## R3. Native shim — surface, language, build

**Decision**: A single C source file (`shim.c`) that exposes a
stable C ABI for ~12 BN254 operations. The C file is a thin wrapper
around gnark-crypto's exported Go functions; gnark-crypto is built
into a static or dynamic library via cgo + `go build -buildmode=c-shared`.
The shim plus gnark-crypto compile into one `.so` / `.dylib` per
target architecture.

**Exposed functions** (final list lives in `contracts/native-abi.md`):

```
siida_bn254_init(void)
siida_bn254_g1_generator(uint8_t *out)
siida_bn254_g2_generator(uint8_t *out)
siida_bn254_g1_scalar_mul(const uint8_t *scalar, const uint8_t *point, uint8_t *out)
siida_bn254_g2_scalar_mul(const uint8_t *scalar, const uint8_t *point, uint8_t *out)
siida_bn254_g1_add(const uint8_t *p, const uint8_t *q, uint8_t *out)
siida_bn254_g2_add(const uint8_t *p, const uint8_t *q, uint8_t *out)
siida_bn254_pairing(const uint8_t *g1, const uint8_t *g2, uint8_t *out)
siida_bn254_pairing_check(const uint8_t *g1s, const uint8_t *g2s, size_t n)
siida_bn254_g2_hash_to_curve(const uint8_t *msg, size_t msg_len, uint8_t *out)
siida_bn254_scalar_from_bytes(const uint8_t *bytes, uint8_t *out)
siida_bn254_g1_subgroup_check(const uint8_t *point)
siida_bn254_g2_subgroup_check(const uint8_t *point)
```

All point/scalar inputs and outputs are fixed-size compressed
encodings (G1: 32 bytes, G2: 64 bytes, GT: 384 bytes, scalar: 32
bytes). Errors are reported via a small set of negative-int return
codes; the Scala layer translates these to typed errors per FR-005.

**Rationale**: A stable C ABI insulates the Scala layer from any
future change in the gnark-crypto API (or even a swap to a different
backing library). The 12-function surface is large enough to build
IBE + BLS + the US3 lower-level primitives, small enough to audit by
inspection. cgo + `c-shared` is the standard Go-to-native-library
recipe.

**Alternatives considered**:

- **Direct cgo `c-archive` linked into a Go binary, no shim.** Would
  require exposing more raw Go internals; harder to keep the FFI
  surface small.
- **gomobile.** Built for Android/iOS bindings; overkill for our
  Linux+macOS shipping targets.

---

## R4. Per-architecture build pipeline

**Decision**: A GitHub Actions matrix job (`.github/workflows/native-build.yml`)
builds the shim+gnark-crypto for four target triples and commits the
results into `modules/crypto/native/<triple>/`:

| Target triple    | Runner               | Output filename       |
|------------------|----------------------|-----------------------|
| `linux-amd64`    | `ubuntu-latest`      | `libsiida_bn254.so`   |
| `linux-arm64`    | `ubuntu-24.04-arm`   | `libsiida_bn254.so`   |
| `darwin-amd64`   | `macos-13` (Intel)   | `libsiida_bn254.dylib`|
| `darwin-arm64`   | `macos-14` (Apple)   | `libsiida_bn254.dylib`|

The matrix job is triggered manually (`workflow_dispatch`) and on
changes to `modules/crypto/native/shim.c`, `modules/crypto/native/go.mod`,
or `modules/crypto/native/build.sh`. It opens a PR with the
regenerated binaries; humans review the binary diffs (small) and
merge.

**Why commit binaries to the repo?** They're load-bearing for
reproducible builds; we want a contributor cloning the repo to get
the same binaries CI used, not whatever a network-fetched download
happens to give them. The binaries are well under 5 MB each, well
within the "small enough to commit" threshold.

**Rationale**: Matches Mill's "smaller dependency surface" rationale
(no runtime binary download), satisfies Principle V's "ship pre-built
binaries", keeps the bootstrap hermetic (no network needed at
`./mill compile` time).

**Alternatives considered**:

- **Build natives at Mill-compile time.** Requires the Go toolchain
  on every developer's machine. Violates 001's "no global install
  beyond JDK 21" promise.
- **Fetch binaries from a CDN at runtime.** Network dependency, no
  hermetic build, hard to audit which exact binary a given JVM is
  running.
- **Ship as a separate artefact / Maven dep.** Possible but adds a
  release process to a project that doesn't have one yet. Defer.

---

## R5. IBE construction

**Decision**: **Boneh-Franklin IBE over a type-3 pairing on BN254**,
preserving the cryptographic semantics of `github.com/vuvuzela/crypto/ibe`.
Specifically:
- Master secret key: random scalar `s ∈ Z_r`.
- Master public key: `g1^s ∈ G1`.
- Per-identity key: `H_G2(identity)^s ∈ G2`, where `H_G2` is the
  hash-to-G2 from R7.
- Encryption (to message `m`, identity `id`, randomness `r`):
  `(g1^r, m ⊕ KDF(e(MPK, H_G2(id))^r))`.
- Decryption (with identity key `dk`): `c2 ⊕ KDF(e(c1, dk))`.
- `KDF` is HKDF-SHA-256, domain-separated with the ASCII tag
  `"siida/ibe/v1/kdf"`.

The KDF tag is the only Siida-specific deviation from the Vuvuzela
ibe wire format and is documented as such in `contracts/ibe.md`.

**Rationale**: The original Vuvuzela construction is the right one
for the threat model; we are preserving semantics, not redesigning.
HKDF-SHA-256 with a domain-separated tag avoids accidental
collision with any other Siida KDF usage and is a strict improvement
over an unkeyed hash.

**Alternatives considered**:

- **Newer IBE schemes (BBG, hierarchical IBE).** Out of scope; would
  be a redesign, not a port. Future spec if needed.

---

## R6. BLS construction

**Decision**: **BLS signatures over BN254 with public keys in G1
and signatures in G2** (the Vuvuzela `crypto/bls` layout — pubkey is
the cheaper G1 element since pubkeys are stored more often than
signatures are produced in Vuvuzela's config chain).
- Private key: random scalar `sk ∈ Z_r`.
- Public key: `g1^sk ∈ G1`.
- Sign(message m): `H_G2(m)^sk ∈ G2`.
- Verify(pk, m, σ): `e(g1, σ) == e(pk, H_G2(m))`.
- Aggregate(σ1..σn): product in G2.
- Verify aggregate over distinct messages: `e(g1, Σσ) == ∏ e(pki, H_G2(mi))`.
- Verify aggregate over same message: `e(g1, Σσ) == e(Σpki, H_G2(m))`.

**Rogue-key resistance**: aggregate-verification REQUIRES proofs of
possession (PoP) on each public key OR distinct-message inputs. We
implement and require proofs of possession at the API level; PoP is
just `BLS.sign(sk, pk_bytes)` with a domain-separated tag.

**Rationale**: Matches upstream Vuvuzela. PoP is the cleanest
rogue-key defence for the config-chain use case (006). The pubkey-in-G1,
sig-in-G2 layout matches the Vuvuzela wire format.

**Alternatives considered**:

- **Pubkeys in G2, sigs in G1 (the "BLS minimal-pubkey-size" variant,
  IETF draft default).** Wider ecosystem alignment, but diverges from
  Vuvuzela. Stay with Vuvuzela's choice for porting fidelity.

---

## R7. Hash-to-curve

**Decision**: **Simplified SWU map for the BN254 G2 curve**, using
the construction in `draft-irtf-cfrg-hash-to-curve-16` (the most
recent stable IETF draft as of early 2026). Domain separation tag:
`"SIIDA-BN254-G2-SSWU-RO-"` (suite suffix `_` plus a per-usage tag,
e.g. `"IBE"`, `"BLS"`, `"POP"`).

Underlying expand-message: `expand_message_xmd` with SHA-256.

**Rationale**: SSWU is the standard hash-to-curve for short Weierstrass
curves; the BN254 G2 variant has known-answer test vectors in the
gnark-crypto test suite. Domain separation per IETF best practice
prevents cross-usage signature/encryption confusion.

**Alternatives considered**:

- **Try-and-increment.** Not constant-time, may leak timing
  information about the message. Rejected.
- **SVDW map.** Older; SSWU is preferred for new code.

---

## R8. Known-answer test vectors

**Decision**: For each cryptographic operation, at least one vector
from a documented external source:

- **BN254 G1/G2 generators, point operations, pairings**: gnark-crypto's
  own test fixtures, pinned by commit hash, copied into
  `modules/crypto/test/resources/bn254_vectors.json`.
- **SSWU hash-to-curve**: vectors from the IETF
  `draft-irtf-cfrg-hash-to-curve-16` appendix.
- **BLS sign / verify / aggregate**: vectors from gnark-crypto's BLS
  tests, restricted to the (pubkey-G1, sig-G2) layout.
- **IBE**: no IETF-standard vectors exist for Boneh-Franklin IBE.
  Generate KATs ourselves using the gnark-crypto-based reference
  implementation, with the master key derived from a fixed seed and
  committed to the test resources. The audit trail relies on the
  KAT generation being deterministic; if a later contributor doubts
  the KATs, they can regenerate from the seed and diff.

Each vector file carries a header comment recording its source URL,
upstream commit hash, and licence. License headers in vector files
are JSON-comment-style; the licence-header check has a small JSON
exemption for files under `*/test/resources/*.json`.

**Rationale**: External vectors decouple "our implementation is
correct" from "our test framework is correct". For IBE, no external
standard exists, but the chain of trust (gnark-crypto → our reference
generator → committed KATs) is short and auditable.

---

## R9. Constant-time guarantees and what isn't constant-time

**Decision**: We rely on gnark-crypto's documented constant-time
arithmetic for the field operations (scalar mul, pairing) that
process secrets. The BLS/IBE Scala layer is **not** explicitly
constant-time but is written to avoid branching on secret data:

- IBE `decrypt` checks ciphertext validity by attempting decryption
  and comparing a computed authenticator; no early-return on
  malformed input that depends on secret bits.
- BLS `verify` operates on public inputs only; constant-time is
  not security-relevant.
- BLS `sign` reduces to scalar-mul through the FFI, where
  gnark-crypto handles it.

Documented in `contracts/threat-model.md`.

**Rationale**: Trying to write constant-time Scala is futile (the
JIT will re-order and short-circuit anyway). Pushing all
secret-touching arithmetic into gnark-crypto and keeping Scala to
public-data branching is the right factoring.

---

## R10. Module layout for `modules/crypto/`

**Decision**:

```
modules/crypto/
├── README.md                     # spec slot pointer (updated to reference 002 specifically)
├── src/
│   ├── siida/crypto/api/         # public Scala API (IBE.scala, BLS.scala, BN254.scala, errors.scala)
│   ├── siida/crypto/internal/    # JNA bindings + byte-buffer marshalling (not exported)
│   └── siida/crypto/internal/ported/   # files ported from vuvuzela/crypto (BSD-3-clause headers preserved)
├── test/
│   ├── src/                      # unit + integration tests (one suite per IBE/BLS/BN254)
│   └── resources/                # KAT vector JSON files
└── native/
    ├── shim.c                    # the C shim wrapping gnark-crypto
    ├── go.mod                    # gnark-crypto pinning
    ├── build.sh                  # one-shot build script invoked by CI matrix
    ├── linux-amd64/libsiida_bn254.so
    ├── linux-arm64/libsiida_bn254.so
    ├── darwin-amd64/libsiida_bn254.dylib
    └── darwin-arm64/libsiida_bn254.dylib
```

The `native/` directory is loaded at JVM startup by a small bootstrap
in `siida.crypto.internal.NativeLoader`, which selects the right
`.so` / `.dylib` based on `os.name` and `os.arch`, extracts it from
the JAR to a tmp dir, and calls `System.load()`.

**Rationale**: Clear separation of concerns: `api/` is the contract,
`internal/` is implementation, `ported/` is the BSD-3-clause origin,
`native/` is non-Scala. The licence-header check (001 FR-010) handles
`api/` and `internal/` as AGPL, `ported/` via the allowlist; `native/`
files are non-Scala and excluded from the check (extension whitelist).

---

## R11. Mill build wiring

**Decision**: In `build.mill`'s `modules.crypto` module:

- Adds `ivy"net.java.dev.jna:jna:5.14.0"` to `ivyDeps`. (Pinned;
  bump in a focused spec.)
- Overrides `resources` to include the per-arch `native/` directory
  so binaries are packaged into the JAR for downstream consumers.
- Defines a `crypto.native.rebuild` Mill task (or a shell script
  invoked from CI) that runs `modules/crypto/native/build.sh` for
  the current host's arch only; CI builds all four arches via the
  matrix job in R4.
- Inherits scalac options from `SiidaModule` (the `-Werror` posture
  remains; gnark-crypto JNA bindings produce no warnings).

**Rationale**: One new dep (JNA), one new resource directory, one
new optional task. Minimal change to 001's build skeleton.

---

## R12. Open questions deferred to later specs

- **Constant-time guarantees for the wider Scala mixnet code** (004).
  This spec covers crypto only; round-handling code in the mixnet
  may itself touch secrets.
- **Hardware-acceleration paths** (AVX-512, ARM SVE) — gnark-crypto
  picks these automatically at runtime; we don't override. If
  performance becomes inadequate, revisit.
- **Post-quantum migration.** BN254 is not post-quantum-secure. A
  future spec may switch to PQC primitives once a stable choice
  emerges. Out of scope.
- **Wider IBE / BLS schemes** (hierarchical IBE, threshold BLS).
  Wait for a concrete need from 005/006/007.
- **Reproducible-build verification for the native binaries**
  (diffoscope, SLSA attestations). Deferred to a release-engineering
  spec.
