#!/usr/bin/env bash
#
# scripts/check-ci-parity.sh — Siida dual-CI parity gate (task T010,
# research R13, constitution Development Workflow & Quality Gates).
#
# Verifies that .github/workflows/ci.yml and .forgejo/workflows/ci.yml
# define the same ordered list of named steps. Drift between the two
# workflow files is the canonical way the two pipelines silently
# diverge; this script makes it a build failure on both sides instead.
#
# Also enforces FR-012: neither workflow may invoke any Go toolchain.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GITHUB_WF="${ROOT}/.github/workflows/ci.yml"
FORGEJO_WF="${ROOT}/.forgejo/workflows/ci.yml"

if [[ ! -f "${GITHUB_WF}" ]]; then
  echo "error: ${GITHUB_WF} not found" >&2
  exit 1
fi
if [[ ! -f "${FORGEJO_WF}" ]]; then
  echo "error: ${FORGEJO_WF} not found" >&2
  exit 1
fi

extract_step_names() {
  # Extract ordered `- name: ...` step labels. Trims whitespace and any
  # surrounding quotes so cosmetic differences don't cause false drift.
  grep -E '^[[:space:]]*-[[:space:]]+name:[[:space:]]+' "$1" \
    | sed -E 's/^[[:space:]]*-[[:space:]]+name:[[:space:]]+//' \
    | sed -E 's/^["'"'"']//; s/["'"'"']$//' \
    | sed -E 's/[[:space:]]+$//'
}

GH_NAMES="$(extract_step_names "${GITHUB_WF}")"
FJ_NAMES="$(extract_step_names "${FORGEJO_WF}")"

if [[ "${GH_NAMES}" != "${FJ_NAMES}" ]]; then
  echo "error: CI step ordering or naming differs between GitHub and Forgejo workflows" >&2
  echo "--- GitHub  (${GITHUB_WF}) ---" >&2
  echo "${GH_NAMES}" >&2
  echo "--- Forgejo (${FORGEJO_WF}) ---" >&2
  echo "${FJ_NAMES}" >&2
  exit 1
fi

# Forbid LEGACY Go-toolchain commands (`go build ./...`, `go test ./...`,
# etc.) running directly against the repo root. Spec 001 FR-012 introduced
# this to keep the deprecated Go scaffolding from being invoked.
#
# Spec 002 introduces a *deliberate* cgo build path under
# modules/crypto/native/ that produces the BN254 native shim. That path
# uses Go legitimately via `actions/setup-go`, `apt-get install golang-go`,
# and `go build -buildmode=c-shared` inside modules/crypto/native/build.sh.
# We allow those uses by anchoring the regex on `go` preceded by whitespace
# or start-of-line, so it doesn't match the `go` inside `setup-go`,
# `golang-go`, `gnark-crypto`, etc.
GO_PATTERN='([[:space:]]|^)go[[:space:]]+(build|test|vet|mod|run)\b'
if grep -E "${GO_PATTERN}" "${GITHUB_WF}" "${FORGEJO_WF}"; then
  echo "error: Legacy Go-toolchain commands detected in CI workflows (002 amends 001 FR-012 to allow cgo native build only)" >&2
  exit 1
fi

echo "[ci-parity] OK — both workflows define the same step sequence (${GH_NAMES//$'\n'/ ; }); no LEGACY Go-toolchain commands (cgo native-shim build is permitted)."
