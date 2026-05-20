# Contract: PKG Directory-Entry Payload Wire Format

**Feature**: [spec.md](../spec.md) · [research R2](../research.md)

This is the byte layout of the payload that the PKG roster
signs over to bind `(identity, mailbox_id, public_bundle)`. It's
the **inner** payload of a `MultiSignedEntry`; the
`MultiSignedEntry` envelope adds its own version byte, signature
tuples, and payload-hash on top.

## Layout

```
offset                  size                       field
─────────────────────  ──────────────────────────  ────────────────────────────
0                      2                           identity_length (uint16 BE)
2                      identity_length             identity_bytes
2 + identity_length    8                           mailbox_id (uint64 BE)
10 + identity_length   1216                        public_bundle_wire_bytes
```

**Total**: `1226 + identity_length` bytes.

The 1216-byte size is fixed by spec 012's
`HybridOnion.serialisePublicBundle` output.

## Field semantics

### identity_length (2 bytes, uint16 BE)

Number of bytes in the identity string. Values 0–65535. The MVP
sets no policy on identity length; a follow-up may add limits.

### identity_bytes (variable)

The identity string as raw bytes. Encoding is application-layer
(typically UTF-8 but not enforced).

### mailbox_id (8 bytes, uint64 BE)

The mailbox-id assigned by the PKG. Values 1..0xFFFE…E (skipping
the reserved 0 and 0xFFFF…F values from spec 004).

### public_bundle_wire_bytes (1216 bytes)

The recipient's `HybridPublicBundle` as serialised by
`HybridOnion.serialisePublicBundle`. Consumers parse this back
to a `HybridPublicBundle` via
`HybridOnion.deserialisePublicBundle`.

## Verifier semantics

Spec 015's `Directory.inMemory` consumes this payload by:

1. Reading the first 2 bytes as `identity_length`
2. Skipping forward by `identity_length` bytes to find the
   `mailbox_id`
3. Skipping past 8 bytes to land at `public_bundle_wire_bytes`
4. Calling `HybridOnion.deserialisePublicBundle` on the
   remaining 1216 bytes

The identity-byte equality check is done by the directory's
lookup index (also bytes-keyed), not by re-parsing the payload.
The verifier-side `MultiSignedEntry.verify` confirms the PKG
roster signed exactly these bytes.

## Why fixed-position?

Could use length-prefixed CBOR / protobuf — but the layout is
fixed (no variable fields except identity), so a hand-rolled
positional layout is simpler and more auditable. Total payload
size is bounded by `1226 + identity_length`, well under any
reasonable buffer limit.

## Compatibility

Future variants (e.g., adding an "issued_at" timestamp,
"expires_at" field) would bump the `MultiSignedEntry.FormatVersion`
from 0x01 → 0x02 — the outer envelope's version byte gates the
payload's internal structure. The MVP does not include
timestamps; a follow-up spec adds expiry when roster rotation
lands.
