# modules/async

Delay-tolerant async delivery for offline recipients, layered over the
mixnet. Provides store-and-forward semantics so a message can be
delivered to a recipient who is offline when the sender posts it,
without leaking the recipient identity through the storage substrate.

This module is a **placeholder** until spec
[`009-async-delivery-over-mixnet`](../../specs/009-async-delivery-over-mixnet/spec.md)
lands. That spec decides the bundle-store substrate (NATS JetStream
vs. dtn7-rs) and the convergence-layer adapter.

Storage substrates (NATS, dtn7) live at the *ingress / async-delivery
boundary* and MUST NOT carry round-aligned mix traffic
(Constitution Principle I).

Do not edit the `Placeholder` here in unrelated PRs.
