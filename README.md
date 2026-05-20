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

- **Language shift to the JVM**: Vuvuzela is Go; Siida targets **Scala 3 +
  Apache Pekko + Cats Effect 3**. Pekko is the Apache Software Foundation's
  Apache-2.0 fork of Akka 2.6.x and is compatible with Siida's AGPL-3.0
  licence; Lightbend's BSL-licensed Akka 2.7+ is not used.
- **Pairing crypto migration**: the cgo / x86-64 assembly `bn256` package
  (dclxvi) used by Alpenhorn is being replaced with the actively maintained
  [`consensys/gnark-crypto/ecc/bn254`][gnark], reached from the JVM either
  through JNI or by a pure-Scala BN254 implementation, depending on the
  outcome of feature `002`. Either way the codebase builds and tests on
  every architecture Pekko supports, including Apple Silicon.
- **Dual CI**: GitHub Actions is the canonical CI for now; a mirror
  Forgejo Actions workflow is maintained so a future move to Codeberg
  is a copy-and-push.
- **Spec-driven development**: feature work happens through
  [GitHub Spec Kit][speckit] (`specs/NNN-*/`). Every migration chunk is a
  numbered feature spec with `spec.md`, `plan.md`, `tasks.md`.
- **Agent-messaging focus**: in addition to human chat, Siida targets
  private message exchange between autonomous AI agents — including the
  case where an agent is offline when a message is sent to it (see
  feature `007`).

[gnark]: https://github.com/Consensys/gnark-crypto
[speckit]: https://github.com/github/spec-kit

## Architectural direction (pre-constitution)

A starting sketch, to be revised and recorded as the project constitution
through `/speckit-constitution`:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Agent ingress boundary    │ NATS / gRPC / typed sockets             │
├─────────────────────────────────────────────────────────────────────┤
│  Siida client SDK          │ Scala 3 + Cats Effect 3 fibers          │
│  (humans + agents)         │ multi-language SDKs later (gRPC)        │
├─────────────────────────────────────────────────────────────────────┤
│  Mixnet core               │ Pekko Cluster + Pekko Streams           │
│  (coordinator / mixers)    │ Pekko Persistence for round durability  │
│  Async delivery (007)      │ NATS JetStream as dead-drop OR dtn7-rs  │
├─────────────────────────────────────────────────────────────────────┤
│  Pairing crypto            │ gnark-crypto via JNI, OR pure-Scala     │
│  (IBE / BLS for PKG)       │ bn254 — decided in feature 002          │
├─────────────────────────────────────────────────────────────────────┤
│  Build / lang              │ Scala 3 + Mill + Apache 2.0 Pekko +     │
│                            │ Cats Effect 3 + http4s                  │
└─────────────────────────────────────────────────────────────────────┘
```

Privacy-sensitive components stay inside the JVM mixnet core; NATS and
DTN-style stores only appear at the *ingress boundary* and the *async
delivery substrate*, never carrying round-aligned mix traffic directly.

## Roadmap

Specs are written and implemented in order. Each lives in `specs/NNN-name/`
with `spec.md`, `plan.md`, `tasks.md`; we use Spec Kit's `/speckit-*`
commands to produce them.

| # | Spec | Scope |
|---|---|---|
| 000 | **Constitution** | Establish project principles, language stack, licence policy, threat-model commitments. Run `/speckit-constitution` first. |
| 001 | `project-bootstrap` | Codify the Scala 3 + Pekko + Cats Effect 3 build, dual CI, repository layout. Revise this scaffold accordingly. |
| 002 | `crypto-pairing` | Replace Alpenhorn's dclxvi `bn256` with a portable BN254 path (JNI to gnark-crypto vs. pure-Scala BN254). Port `ibe` and `bls`. |
| 003 | `dependency-automation` | Weekly Scala Steward GitHub Actions workflow for JVM dependency bumps. Pins respect constitution v1.0.0 stack lines. Go side of the build excluded. |
| 004 | `mixnet-server` | Coordinator + mixer chain + deterministic shuffle on top of `HybridOnion` (012). MVP shipped 2026-05-20: single-JVM, in-memory round execution. Distributed deployment, persistence, crash recovery, live roster rotation, and observability are deferred to follow-up specs. |
| 005 | `pkg-keybootstrap` | Private Key Generator: identity onboarding + signed directory entries consumed by 015. MVP shipped 2026-05-20: in-memory single-PKG state, `issueIdentity` + `directorySnapshot` end-to-end against 015's `IdentityEncryption`. Friend-discovery (Alpenhorn add-request flow), persistent storage, network transport, sybil resistance, and roster rotation are deferred to follow-up specs. |
| 006 | `config-chain-governance` | PKG operations and signed config-chain governance: the social-trust hinge that controls who is in the mixer/PKG set and how that membership rotates. MVP shipped 2026-05-20: in-memory append-only chain over `MultiSignedEntry`; `ConfigChain.{genesis, append, head, currentView, at, history}` with epoch monotonicity, predecessor linkage, replay detection, threshold enforcement. Network distribution, persistent storage, multi-signer coordination, anti-equivocation, observability are deferred to follow-up specs. |
| 007 | `client-sdk` | Scala client SDK on Cats Effect 3 fibers. Wire formats, retransmission, config-chain verification. MVP shipped 2026-05-20: local-composition `SiidaClient` with `sendChatMessage`, `sendAddRequest`, `coverSubmission`, `deliver`. Network transport, persistent state, Cats Effect 3 fibers, retransmission, multi-recipient broadcast are deferred to follow-up specs. |
| 008 | `agent-messaging` | The new layer: APIs and conventions for autonomous AI agents to exchange messages over Siida. MVP shipped 2026-05-20: `AgentEnvelope` (SIAG magic + kind + request_id + content) inside 007's chat-message payload; `AgentClient` thin wrapper around `SiidaClient` with `sendRequest`, `sendResponse`, `sendNotification`, `deliverAgent`. Raw chat without the SIAG prefix surfaces as `RawChat` (best-effort fall-through). Capability negotiation, JSON-RPC framing, in-flight request tracking, identity conventions are deferred. |
| 009 | `async-delivery-over-mixnet` | Delay-tolerant store-and-forward for offline recipients, layered over the mixnet. NATS JetStream or `dtn7-rs` as the bundle store; convergence-layer adapter. MVP shipped 2026-05-20: `Mailroom` trait with `inMemory(ttl)` and `persistent(path, ttl)` impls. TTL with lazy expiry; cover/broadcast mailboxes dropped on deposit; atomic-rewrite file-backed store with SIMR magic. NATS/dtn7 bindings, concurrency, ACKs, encryption-at-rest are deferred. |
| 010 | `chat-client` (sketched) | Replaces Vuvuzela's terminal `gocui` UI; cross-platform Scala client. MVP shipped 2026-05-20: headless `ChatSession` model aggregating `SiidaClient` + `FriendStore`, with `sendChat(alias, text)`, `deliverInbound(envelope)`, `friends`, `lookup`, `history`. UI layers (TUI, GUI) are follow-ups. |
| 011 | `post-quantum-roadmap` | Threat-model amendment + per-primitive PQ replacement plan. Anchors choices to European certifications (BSI / ANSSI / ENISA) with Swedish research provenance noted; reserves slots 012–015 for the per-primitive migrations. Constitution amendment to v2.0.0 expected. |
| 012 | `pq-mixnet-onion-layer` (sketched) | Hybrid ML-KEM-768 + x25519 for the round-aligned onion layers, replacing the classical-only NaCl `box`. |
| 013 | `pq-bls-replacement` (sketched) | ML-DSA-65 for per-signer signatures, losing the BLS aggregation property. |
| 014 | `pq-config-chain-redesign` (sketched) | Config-chain governance without aggregate signatures (batch verification of ML-DSA) or via a separate aggregate-friendly PQ scheme. |
| 015 | `pq-identity-encryption` (sketched) | Replace Boneh-Franklin IBE with a PKG-directory + ML-KEM scheme; protocol-level redesign. |
| 016 | `audit-pq-conformance` | Verify Bouncy Castle's ML-KEM-768 and ML-DSA-65 match FIPS 203 / 204 byte-for-byte against NIST ACVP vectors. Diagnostic-only; produces a conformance report + CI-enforced audit suite that catches regressions on future BC bumps. |
| 017 | `bc-version-bump` | Bump `bcprov-jdk18on` 1.78.1 → 1.84 to close the FIPS 203 / 204 conformance gap surfaced by 016. Audit suite verifies the result; baseline constants update; report appended. Small, mechanical, gated by 016. |
| 018 | `observability` (sketched) | OpenTelemetry, ops dashboards. Bumped from 017 by the bc-version-bump insertion. MVP shipped 2026-05-20: `Telemetry` trait with `incrementCounter`, `recordGauge`, `recordHistogram`, `snapshot`. `Telemetry.inMemory()` single-threaded impl + `Telemetry.noop` singleton. Wiring into existing modules (Coordinator, Mailroom, PKG), OTEL exporter, concurrent impl, sampling/windowing are deferred to follow-up specs. |
| 019 | `friend-discovery` | Alpenhorn-style add-request primitive (alice → bob). MVP shipped 2026-05-20: `Friendship.{buildAddRequest, processAddRequest, verifyAddRequest}` + in-memory `FriendStore`. Mixnet routing, add-response, friendship-key dial tokens, persistent store, and revocation are deferred to follow-up specs. |
| 020 | `friend-discovery-followups` | Add-response half (bob → alice), deterministic `Friendship.deriveFriendshipKey` (symmetric per-pair secret from public bundles + add-id; stand-in for Alpenhorn's IBE-based dial tokens removed by 015), and persistent `FriendStore` (atomic file-backed store with SIFD magic). MVP shipped 2026-05-20. Full Alpenhorn dial tokens, revocation, unfriend, and encryption-at-rest of the persistent store are deferred to follow-up specs. |

## Build

Siida is **JVM-only** as of constitution v1.0.0. The canonical bootstrap
on a clean machine is:

```sh
make check        # headers + compile + test + ci-parity (same as CI)
```

The Makefile wraps `./mill`, which reads `.mill-version` and self-fetches
the pinned Mill release into a project-local cache; no global Mill or
Scala install is required. `make help` lists individual targets. The only host prerequisite is **JDK 21 LTS**
(Temurin recommended). See [`specs/001-project-bootstrap/quickstart.md`](specs/001-project-bootstrap/quickstart.md)
for the full developer entry point.

> **Note on `go.mod`**: the file at the repository root is a historical
> artefact from an early Go exploration and is **retained for git-history
> continuity only**. Do not attempt to build Siida with the Go toolchain;
> the constitution mandates the JVM-native stack (Scala 3 + Apache Pekko
> + Cats Effect 3, built by Mill). Neither CI pipeline invokes any Go
> command, and `scripts/check-ci-parity.sh` enforces this on every push.

## Status

**Pre-alpha.** Bootstrap scaffold in place; constitution v1.0.0 ratified
on 2026-05-16; feature 001-project-bootstrap landing the Mill build is
in flight.

## Lineage and licence

The mixnet protocol, coordinator, and PKG code originate from Vuvuzela
(© 2015–2016 David Lazar, with contributions from Jelle van den Hooff,
Nickolai Zeldovich, and Matei Zaharia) and Alpenhorn (© 2016 David Lazar),
both **AGPL-3.0-or-later**. Siida is a derivative work and retains the same
licence. See `LICENSE` and `NOTICE` for full attribution.

Cryptographic primitives derived from earlier permissively-licensed code
(Go's bn256 implementation, dclxvi, etc.) retain their original BSD-3-clause
headers at file scope.
