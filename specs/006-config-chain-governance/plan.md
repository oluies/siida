# Implementation Plan: 006-config-chain-governance (MVP)

**Branch**: `006-config-chain-governance`

## Technology stack

- Scala 3.6.4 (existing project), JDK 21, Mill 0.12.11.
- No new external dependencies. Reuses
  `siida.crypto.api.{PqSignature, MultiSignedEntry}` and JDK
  `MessageDigest("SHA3-256")`.

## Project structure

```
modules/configchain/
  src/siida/configchain/api/
    Errors.scala           - ConfigChainError ADT
    ConfigEntry.scala      - payload codec + entry construction
    ConfigChain.scala      - chain trait + in-memory impl
  test/src/
    ConfigEntrySuite.scala
    ConfigChainSuite.scala
    GenesisSuite.scala
```

## Wire format (FormatVersion 0x01)

`payload = 1B version || 8B epoch || 32B prev_hash || 2B n_roster
|| n × 1953B PqSignature pubkeys || 2B new_threshold || extension`.

Whole entry on the wire = `MultiSignedEntry` (014) carrying this
payload. Entry hash = `SHA3-256(MultiSignedEntry.serialise(entry))`.

## Constitution check (v2.0.0)

Pass. No new crypto primitive; pure composition of 013 + 014 with
chain-state semantics.

## Module dependencies

`modules.configchain.moduleDeps = Seq(modules.crypto)` — needs
PqSignature + MultiSignedEntry. No mixnet dep.
