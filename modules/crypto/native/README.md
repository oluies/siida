# modules/crypto/native

The native pairing shim. Wraps
[gnark-crypto](https://github.com/Consensys/gnark-crypto)'s BN254
primitives behind the C ABI documented in
[`../../../specs/002-crypto-pairing/contracts/native-abi.md`](../../../specs/002-crypto-pairing/contracts/native-abi.md).

Built as a `c-shared` library via cgo:

```sh
# host-arch build (the maintainer's bootstrap path)
bash build.sh

# explicit per-arch build
GOOS=linux  GOARCH=amd64 bash build.sh
GOOS=linux  GOARCH=arm64 bash build.sh
GOOS=darwin GOARCH=amd64 bash build.sh
GOOS=darwin GOARCH=arm64 bash build.sh
```

Output: `./<triple>/libsiida_bn254.{so,dylib}`. The `<triple>`
directories are committed to git and packaged into the Siida JAR
(via the `modules.crypto.resources` override in `build.mill`); the
Scala `NativeLoader` extracts the matching binary at JVM startup
and `System.load()`s it.

## Architecture matrix

| Target            | Runner               | Output                  |
|-------------------|----------------------|-------------------------|
| `linux-amd64`     | `ubuntu-latest`      | `libsiida_bn254.so`     |
| `linux-arm64`     | `ubuntu-24.04-arm`   | `libsiida_bn254.so`     |
| `darwin-amd64`    | `macos-13` (Intel)   | `libsiida_bn254.dylib`  |
| `darwin-arm64`    | `macos-14` (Apple)   | `libsiida_bn254.dylib`  |

The full matrix is rebuilt by
[`.github/workflows/native-build.yml`](../../../.github/workflows/native-build.yml)
on `workflow_dispatch` or on changes to `main.go` / `go.mod` /
`build.sh`. The job opens a PR with the regenerated binaries; humans
review the binary diffs (small) and merge.

A fifth target architecture is not supported in 002. Adding one
requires either: extend the matrix and rebuild, or amend the spec
to introduce a pure-Scala fallback path. See
[`research.md`](../../../specs/002-crypto-pairing/research.md) R4.

## Local prerequisites

- Go 1.22 or newer (matches the `go.mod` directive)
- A working C toolchain (Xcode CLT on macOS; `build-essential` on
  Debian/Ubuntu) — cgo needs `cc` to link

No global gnark-crypto install is required; `go build` resolves it
into the local Go module cache.
