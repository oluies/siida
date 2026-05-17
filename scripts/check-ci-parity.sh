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

# Forbid Go-toolchain commands anywhere in either workflow (FR-012, US3).
GO_PATTERN='(\bgo[[:space:]]+(build|test|vet|mod|run)\b|actions/setup-go|setup-go@)'
if grep -E "${GO_PATTERN}" "${GITHUB_WF}" "${FORGEJO_WF}"; then
  echo "error: Go-toolchain commands detected in CI workflows (FR-012)" >&2
  exit 1
fi

echo "[ci-parity] OK — both workflows define the same step sequence (${GH_NAMES//$'\n'/ ; }); no Go toolchain invocations."
