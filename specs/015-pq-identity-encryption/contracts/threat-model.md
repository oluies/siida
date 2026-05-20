# Contract: Privacy threat-model delta — PKG-Directory vs Boneh-Franklin IBE

**Feature**: [spec.md](../spec.md) · [research R2](../research.md)

This document is the load-bearing trade-off the spec commits to.
Read this BEFORE accepting the rest of 015.

## What Boneh-Franklin IBE gave us (spec 002, v1.0.0)

A sender could encrypt to a recipient identity without any
per-message PKG interaction. The PKG saw:

- Master key generation (one-time, no per-message exposure)
- Per-identity decryption key issuances (one-time per identity)

The PKG did **NOT** see who was about to encrypt to whom. That's
the contribution Boneh-Franklin IBE made to metadata privacy:
encryption is unilateral.

## What this spec gives us (015, v2.0.0)

A sender encrypts to a recipient by:

1. Looking up the recipient's `HybridPublicBundle` in the PKG-
   directory
2. Calling `HybridOnion.encrypt` with the bundle

The PKG sees:

- Master/roster issuances (same as before)
- **Every directory lookup**: identity X being queried for, at
  time T, by query Y

This is a real privacy regression. A compromised or curious PKG
can build:

- A "who wants to talk to whom" graph from query→identity bindings
- A timing graph of when interactions happen
- A query-volume estimate per identity (popularity, social
  centrality)

The IBE's "encryption is unilateral" property is **lost**.

## What mitigates it

### Anonymous-routed lookups (FR-007, mandatory)

The SDK (spec 007) routes directory queries through Siida's own
mixnet. The PKG sees:

- Query Y arrived at time T asking for identity X
- The mixnet ingress that delivered Y (NOT the original sender)

The PKG cannot attribute Y to a specific sender — the mixnet's
metadata-privacy guarantee (Constitution Principle I) applies
to PKG-bound traffic the same way it applies to recipient-bound
traffic. The PKG is just another recipient on the network.

**Residual leak**: the PKG still sees per-query identity-being-
looked-up and timing. It does not see "who looked up." An
adversary with PKG access cannot rebuild the social graph; an
adversary with both PKG access AND mixnet-egress observability
(which the GPA threat model already covers) cannot either,
because the mixnet's anonymity set covers the lookup traffic.

### Pre-fetch full directory (optional, high bandwidth)

For high-assurance clients that cannot tolerate per-query
exposure, the SDK MAY pre-fetch the full directory. Bandwidth:
~1.2 GB for 1 million identities (1216 bytes per bundle), more
with signatures. Reserve for clients who can afford the
bandwidth.

### Padded query rate (recommended)

Per spec 007's design: the SDK's directory-query layer SHOULD
emit a steady rate of queries (real + cover) so the PKG cannot
infer activity bursts from query volume.

### Query rate caps (recommended)

Per spec 005's design: the PKG SHOULD cap query rate per
ingress to prevent traffic-analysis attacks that exploit a high
fan-out from one sender.

## What this spec does NOT mitigate

| Risk | Why not |
|---|---|
| PKG learns popular identities (query distribution) | Inherent — popular identities are queried more |
| PKG learns peak interaction times (timing) | Padded queries help but don't eliminate |
| PKG can withhold legitimate entries (denial of service) | The signed config chain (006) lets clients detect missing entries; PKG can be replaced if confirmed malicious |
| PKG can publish wrong bundles (active attack) | The MultiSignedEntry chain provides integrity but only against the PKG roster's threshold — if M-of-N roster is corrupted, integrity breaks |

The last two are governance / threat-model concerns that 005 and
006 handle, not crypto-level mitigations.

## Comparison summary

| Property | Boneh-Franklin IBE (002, v1.0.0) | PKG-Directory + HybridOnion (015, v2.0.0) |
|---|---|---|
| Quantum-safe | NO (BN254 breakable by Shor) | YES (ML-KEM-768 + x25519 hybrid) |
| Sender→PKG metadata exposure | None | Per-query identity + timing |
| Mitigation cost | N/A | Mixnet round-trip per lookup |
| Bandwidth per encryption | Constant | Constant after directory cached |
| Sender can encrypt offline | YES (with master pubkey only) | NO (requires directory) |
| Identity-key derivation | Deterministic from master + id | Stored explicitly per identity |

The "sender can encrypt offline" loss is the operational cost
of the migration. It mostly affects edge cases — agents that
preencrypt batch messages without network access, or clients in
truly offline conditions. The 007 SDK's caching layer mitigates
for the common case (recently-seen identities cached locally).

## Summary

This spec is the load-bearing PQ migration for identity-addressed
encryption. The cost is real: PKG visibility into per-query
lookups. The mitigation is the same mixnet that already provides
metadata-privacy for recipient-bound traffic; anonymous routing
of PKG queries closes the gap to "PKG sees what it's queried for,
not who's querying."

Constitution v2.0.0 explicitly accepts this trade-off in the
Security & Threat Model section's PQ-posture bullet. The
alternative — wait for production-grade PQ-IBE — would leave
Siida's identity-addressed encryption flow quantum-vulnerable for
an indefinite period.
