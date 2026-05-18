#!/usr/bin/env bash
#
# Siida native pairing shim — build script.
# Invoked per-arch by the CI matrix or locally for the host arch.
#
# Usage:
#   bash modules/crypto/native/build.sh              # build for the host arch
#   GOOS=linux  GOARCH=amd64 bash build.sh           # explicit per-arch
#   GOOS=linux  GOARCH=arm64 bash build.sh
#   GOOS=darwin GOARCH=amd64 bash build.sh
#   GOOS=darwin GOARCH=arm64 bash build.sh
#
# Output: modules/crypto/native/<triple>/libsiida_bn254.{so,dylib}

set -euo pipefail

cd "$(dirname "$0")"

GOOS_VAL="${GOOS:-$(go env GOOS)}"
GOARCH_VAL="${GOARCH:-$(go env GOARCH)}"

case "${GOOS_VAL}" in
  linux)  EXT="so" ;;
  darwin) EXT="dylib" ;;
  *) echo "[siida-native] unsupported GOOS: ${GOOS_VAL}" >&2; exit 1 ;;
esac

TRIPLE="${GOOS_VAL}-${GOARCH_VAL}"
OUTDIR="$(pwd)/${TRIPLE}"
OUTFILE="${OUTDIR}/libsiida_bn254.${EXT}"

mkdir -p "${OUTDIR}"

echo "[siida-native] building ${TRIPLE} -> ${OUTFILE}"

CGO_ENABLED=1 GOOS="${GOOS_VAL}" GOARCH="${GOARCH_VAL}" \
  go build -buildmode=c-shared -o "${OUTFILE}" .

# Drop the .h header that `go build -buildmode=c-shared` writes next
# to the .so/.dylib; JNA doesn't need it and shipping it would just be
# noise in the JAR.
rm -f "${OUTDIR}/libsiida_bn254.h"

echo "[siida-native] ok: $(ls -lh "${OUTFILE}" | awk '{print $5, $NF}')"
