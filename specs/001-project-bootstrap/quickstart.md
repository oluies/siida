# Quickstart: Project Bootstrap

**Feature**: [spec.md](./spec.md) · **Plan**: [plan.md](./plan.md)

This quickstart documents the contract between the project and a new
contributor (human or agent) on a fresh machine. If anything below stops
working, the bootstrap is broken — file an issue against this spec.

## Prerequisites

- **JVM 21 LTS** (Temurin recommended). Any JDK 21.0.x is acceptable.
  Verify with `java -version` showing `21.0.x`.
- **git** (any recent version).
- Nothing else. In particular: **no global Mill, no global Scala, no
  Go toolchain** is required.

Apple Silicon (macOS arm64) and Linux x86_64 are both supported developer
platforms.

## Clone and build

```bash
git clone https://github.com/oluies/siida.git
cd siida
make check                  # headers + compile + test + ci-parity
```

`make check` is the same sequence CI runs. Individual steps are
available too:

```bash
make build        # compile every module
make test         # run every module's smoke test
make headers      # licence-header check only
make ci-parity    # GitHub vs Forgejo workflow parity
make help         # list everything
```

The Makefile is a thin wrapper over the `./mill` launcher pinned in
`.mill-version`; on first run Mill downloads itself into the
project-local cache. No global Mill or Scala install is required.
Total cold-cache time on a typical laptop: **under 5 minutes**.

## What "success" looks like

- `make check` exits with code `0`.
- `make test` reports one passing test per module (`core`, `crypto`,
  `mixnet`, `pkg`, `configchain`, `sdk`, `agent`, `async` — eight
  modules total).
- `make headers` exits with code `0` (licence-header enforcement).

## Per-module work

When you start a numbered feature (002, 003, …), open the matching
module under `modules/<name>/`. Each module's `README.md` names the
spec it expects to be filled by:

| Module          | Spec slot                  |
|-----------------|----------------------------|
| `core`          | shared primitives          |
| `crypto`        | 002-crypto-pairing         |
| `mixnet`        | 003-mixnet-server          |
| `pkg`           | 004-pkg-keybootstrap       |
| `configchain`   | 005-config-chain-governance|
| `sdk`           | 006-client-sdk             |
| `agent`         | 007-agent-messaging        |
| `async`         | 008-async-delivery-over-mixnet |

Until that spec is opened the module contains a single `Placeholder`
object and one passing smoke test. Do not edit the placeholder in
unrelated PRs.

## CI

Every push and every pull request runs the same logical sequence on:

- **GitHub Actions** (canonical) — Linux/amd64, Temurin 21.
- **Forgejo Actions** (mirror) — Linux/amd64, `eclipse-temurin:21-jdk`
  container.

Both runs must be green for a PR to merge. Drift between the two
workflow files is caught by `scripts/check-ci-parity.sh`, which runs in
both pipelines.

## Troubleshooting

- **"`java` not found" or "`UnsupportedClassVersionError`"**: install
  JDK 21 (Temurin or equivalent). The `./mill` launcher requires it.
- **Network blocked**: the first run downloads Mill, Scala, Pekko, and
  Cats Effect 3 artefacts from Maven Central. Configure your HTTP(S)
  proxy or use an artefact mirror.
- **Licence-header failure on a new file**: copy the header block from
  `build/licence-headers/agpl.txt` to the top of the new source file
  (or to the new ported file's allowlist entry, with original
  copyright preserved).
- **The smoke test passes locally but CI fails**: check
  `scripts/check-ci-parity.sh` output — drift between the two workflow
  files is the most likely cause.

## Validation checklist (for spec verification, not contributors)

- [ ] Fresh clone → `./mill __.compile` succeeds within 5 minutes
      (SC-001).
- [ ] Fresh clone → `./mill __.test` succeeds with 8 passing tests.
- [ ] Both CI pipelines complete within 10 minutes per push (SC-002).
- [ ] Every roadmap area 002–008 has exactly one placeholder module
      (SC-003).
- [ ] A PR that omits the AGPL header on a new file is blocked by CI
      (SC-006).
