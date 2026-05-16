# Siida

> *Siida* (Northern Sámi): a community of related actors moving together —
> originally a reindeer-herding band, sharing pastures and trails through the
> seasons. Here: a network of users and agents whose conversations move
> together through the same mix chain, indistinguishable from one another to
> any outside observer.

Siida is a privacy-preserving messaging system for **human chat** and
**AI-agent-to-agent messaging**. It is derived from the [Vuvuzela][vuv]
research project (David Lazar et al., MIT CSAIL, SOSP 2015) and its companion
[Alpenhorn][alp] key-bootstrap system.

[vuv]: https://github.com/vuvuzela/vuvuzela
[alp]: https://github.com/vuvuzela/alpenhorn

## What it inherits from Vuvuzela

Strong **metadata privacy**: even a global passive adversary who can observe
every packet on every link cannot tell *who is talking to whom*. This is
achieved by:

- **Round-based mixing**: clients submit one onion-encrypted message per
  round, in lockstep, whether they have something to say or not (cover
  traffic).
- **An onion-routed mix chain**: each mixer strips one layer of NaCl
  `box` encryption and shuffles the batch before forwarding.
- **Calibrated noise**: mixers inject differentially-private dummy traffic
  so the small leaks that can't be encrypted (number of active users) are
  obscured.

## What is new in Siida

- **Modernised toolchain**: Go modules, Go 1.26, dual CI for GitHub Actions
  and Codeberg / Forgejo Actions.
- **Pairing crypto migration**: the cgo / x86-64 assembly `bn256` package
  (dclxvi) is being replaced with the pure-Go, actively maintained
  [`consensys/gnark-crypto/ecc/bn254`][gnark]. This makes the codebase build
  and test on every architecture Go targets, including Apple Silicon.
- **Spec-driven development**: feature work happens through
  [GitHub Spec Kit][speckit] (`specs/NNN-*/`). Every migration chunk —
  bootstrap, crypto port, mixnet port, agent-messaging layer — is a numbered
  feature spec with `spec.md`, `plan.md`, `tasks.md`.
- **Agent-messaging focus**: in addition to human chat, Siida targets
  private message exchange between autonomous AI agents.

[gnark]: https://github.com/Consensys/gnark-crypto
[speckit]: https://github.com/github/spec-kit

## Status

**Pre-alpha.** Project bootstrap in progress. See `specs/` for the active
feature pipeline.

## Lineage and licence

The mixnet protocol, coordinator, and PKG code originate from Vuvuzela
(© 2015–2016 David Lazar, with contributions from Jelle van den Hooff,
Nickolai Zeldovich, and Matei Zaharia) and Alpenhorn (© 2016 David Lazar),
both **AGPL-3.0-or-later**. Siida is a derivative work and retains the same
licence. See `LICENSE` and `NOTICE` for full attribution.

Cryptographic primitives derived from earlier permissively-licensed code
(Go's bn256 implementation, dclxvi, etc.) retain their original BSD-3-clause
headers at file scope.
