# Contract: IdentityCiphertext Wire Format

**Feature**: [spec.md](../spec.md) · [research R4](../research.md)

```
offset  size       field
0       1          algorithm ID (0x20 for this spec)
1       1137       HybridOnion.OnionLayer fixed envelope (per spec 012)
1138    N          HybridOnion.OnionLayer payload portion (variable)
```

Total: `1138 + |payload|` bytes.

The 012 `OnionLayer` wire format is reused verbatim — the
`IdentityCiphertext` envelope is a 1-byte prefix that lets the
mixnet / SDK distinguish "identity-addressed message" from other
onion-layered traffic without parsing into the 012 envelope.

## Algorithm-ID space

| ID    | Meaning                                              | Status |
|-------|------------------------------------------------------|--------|
| 0x20  | Identity-addressed encryption v1 (this spec)         | CURRENT |
| 0x21–0x2F | Reserved for future identity-encryption variants  | RESERVED |

Distinct from 012's onion-layer IDs (0x00–0x0F) and 013's
signature IDs (0x10–0x1F), so the single wire-format byte tells
the recipient what they're holding.

## Refusal rule

A recipient receiving a ciphertext whose algorithm ID isn't
implemented MUST refuse with `UnsupportedAlgorithm`. Refusal is
uniform — no side channel about which IDs are supported.
