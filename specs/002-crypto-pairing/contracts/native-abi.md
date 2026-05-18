# Contract: Native ABI exposed by `libsiida_bn254.{so,dylib}`

**Feature**: [spec.md](../spec.md) · **Implementation strategy**: [research.md R3](../research.md)

The native shim wraps gnark-crypto's BN254 implementation behind a
small C ABI. The Scala layer reaches it via JNA (`research.md` R2).
The same ABI is implemented on every supported architecture so the
JNA bindings are arch-independent.

## C ABI

```c
// All byte buffers are caller-allocated, fixed-size compressed
// encodings:
//   scalar   : 32 bytes, big-endian, reduced mod r
//   G1 point : 32 bytes (compressed)
//   G2 point : 64 bytes (compressed)
//   GT elem  : 384 bytes
//
// Return value convention:
//   0           on success
//   negative    on error (codes below)

#define SIIDA_OK                       0
#define SIIDA_ERR_INVALID_ENCODING    -1
#define SIIDA_ERR_NOT_ON_CURVE        -2
#define SIIDA_ERR_NOT_IN_SUBGROUP     -3
#define SIIDA_ERR_INVALID_LENGTH      -4
#define SIIDA_ERR_INTERNAL            -99

// Lifecycle — must be called exactly once per JVM, before any other op.
int siida_bn254_init(void);

// Generators
void siida_bn254_g1_generator(uint8_t out[32]);
void siida_bn254_g2_generator(uint8_t out[64]);

// Group operations
int siida_bn254_g1_scalar_mul(const uint8_t scalar[32], const uint8_t point[32], uint8_t out[32]);
int siida_bn254_g2_scalar_mul(const uint8_t scalar[32], const uint8_t point[64], uint8_t out[64]);
int siida_bn254_g1_add(const uint8_t p[32], const uint8_t q[32], uint8_t out[32]);
int siida_bn254_g2_add(const uint8_t p[64], const uint8_t q[64], uint8_t out[64]);

// Pairings
int siida_bn254_pairing(const uint8_t g1[32], const uint8_t g2[64], uint8_t out[384]);

// Multi-pairing check: e(g1[0], g2[0]) * ... * e(g1[n-1], g2[n-1]) == 1
// g1s/g2s are tightly packed arrays of n elements each.
// Returns:
//   0  if check holds
//   1  if check does not hold (NOT an error; legitimate False)
//  <0  on encoding error
int siida_bn254_pairing_check(const uint8_t *g1s, const uint8_t *g2s, size_t n);

// Hash-to-curve (SSWU map, expand_message_xmd with SHA-256)
int siida_bn254_g2_hash_to_curve(
  const uint8_t *msg, size_t msg_len,
  const uint8_t *dst, size_t dst_len,  // domain separation tag
  uint8_t out[64]);

// Subgroup checks (callable on freshly-deserialised points)
int siida_bn254_g1_subgroup_check(const uint8_t point[32]);
int siida_bn254_g2_subgroup_check(const uint8_t point[64]);

// Scalar utility — reduces input bytes mod r (handles 32-byte input;
// for caller convenience when generating scalars from a hash output)
void siida_bn254_scalar_reduce(const uint8_t in[32], uint8_t out[32]);
```

## ABI stability

- Function names, signatures, return-code values, and byte-buffer
  sizes are part of the contract. Any change requires bumping a
  `siida_bn254_abi_version` constant (not yet defined; introduce in
  a follow-up if a breaking change is needed).
- The shim does NOT expose Go's internal types. Every pointer crosses
  the boundary as `uint8_t *` of a fixed length.
- The shim does NOT allocate heap memory across the FFI boundary;
  all output buffers are caller-allocated. This keeps JNA marshalling
  trivial and avoids cross-runtime GC concerns.

## Library naming and discovery

The binaries live on disk under `modules/crypto/native/<triple>/`,
which Mill's `resources` override mounts at the JAR classpath root
(the `modules/crypto/native/` segment is stripped, so the binaries
sit directly under `/<triple>/` on the classpath).

| Triple         | Path on disk                                   | Path on the JVM classpath          |
|----------------|------------------------------------------------|-------------------------------------|
| linux-amd64    | `modules/crypto/native/linux-amd64/libsiida_bn254.so`     | `/linux-amd64/libsiida_bn254.so`     |
| linux-arm64    | `modules/crypto/native/linux-arm64/libsiida_bn254.so`     | `/linux-arm64/libsiida_bn254.so`     |
| darwin-amd64   | `modules/crypto/native/darwin-amd64/libsiida_bn254.dylib` | `/darwin-amd64/libsiida_bn254.dylib` |
| darwin-arm64   | `modules/crypto/native/darwin-arm64/libsiida_bn254.dylib` | `/darwin-arm64/libsiida_bn254.dylib` |

The Scala bootstrap (`siida.crypto.internal.NativeLoader`) inspects
`os.name` + `os.arch`, fetches the matching binary from the classpath
via `getResourceAsStream`, copies it to a temp file with the correct
suffix, and calls JNA's `Native.load(absolutePath, classOf[NativeBN254])`
to dlopen it. Unsupported architectures fail loudly at JVM startup
with a typed `UnsupportedNativeArchException` (NOT a typed error
return) — this is a programming-environment failure, not a per-call
condition, and follows the FR-005 carve-out for resource failures.
