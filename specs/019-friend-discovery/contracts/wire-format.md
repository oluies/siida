# Contract: Friend Discovery Wire Formats

**Feature**: [spec.md](../spec.md) · [research R2](../research.md)

## AddRequest (ciphertext)

```
offset  size       field
0       1          algorithm ID (0x30 — AddRequest_v1)
1       *          HybridOnion.OnionLayer bytes (1137 + |payload|)
```

The HybridOnion.OnionLayer wraps the AddRequestContent
plaintext (1218 + sender_identity_len bytes). Total ciphertext:
`1 + 1137 + 1218 + sender_identity_len` = `2356 + sender_identity_len`
bytes.

## AddRequestContent (plaintext, carried inside the AEAD ciphertext)

```
offset             size       field
0                  2          sender_identity_length (uint16 BE)
2                  N          sender_identity_bytes
2 + N              1216       sender_public_bundle (HybridOnion.serialisePublicBundle)
```

Total plaintext: `1218 + sender_identity_length` bytes.

## Algorithm-ID space allocation (PKG / discovery)

| ID    | Meaning                                              | Status |
|-------|------------------------------------------------------|--------|
| 0x30  | AddRequest_v1 (this spec)                            | CURRENT |
| 0x31  | Reserved for AddResponse_v1                          | RESERVED |
| 0x32  | Reserved for friendship-key dial-token registration  | RESERVED |
| 0x33–0x3F | Reserved for future friend-discovery variants   | RESERVED |

Future variants get new alg-IDs in this space. The byte at
offset 0 is the single source of truth for which decode path to
use.

## Uniform refusal

A deserialise call seeing a first byte != `0x30` MUST return
`Left(UnsupportedAlgorithm)` with no per-ID logging or per-ID
error variance — same constant-timing discipline as 013, 014,
015, 005.

## Composition with the mixnet

When the SDK (spec 007) ships add-requests over the mixnet, the
AddRequest ciphertext is the **inner payload** of a
`MixChain.MailboxEnvelope` (8-byte mailbox_id + payload). The
envelope is then layered by `MixChain.layeredSubmission` through
the mixer chain. Spec 019 ships only the inner AddRequest
construction; the outer wrapping is the SDK's job.

So a full on-wire add-request submission looks like:

```
[Onion layer 1 (1137 bytes)]
  └── encrypted under mixer #1's bundle, contains:
[Onion layer 2 (1137 bytes)]
  └── encrypted under mixer #2's bundle, contains:
[Onion layer 3 (1137 bytes)]
  └── encrypted under mixer #3's bundle, contains:
[MailboxEnvelope]
  ├── 8 bytes mailbox_id (bob's mailbox per PKG directory)
  └── [AddRequest ciphertext]
        ├── 1 byte alg-ID (0x30)
        └── HybridOnion.OnionLayer (encrypted to bob's bundle)
              └── AEAD ciphertext containing:
                    [AddRequestContent plaintext]
                      ├── 2 bytes identity length
                      ├── N bytes alice's identity
                      └── 1216 bytes alice's public bundle
```

Four nested layers of HybridOnion (three mixer layers + the
inner AddRequest layer to bob). Each layer's HNDL-resistance is
inherited from 012.
