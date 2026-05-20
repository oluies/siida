// Siida — privacy-preserving messaging for human chat and AI-agent
// messaging. Derived from Vuvuzela (David Lazar et al., SOSP 2015) and
// the Alpenhorn key-bootstrap system.
//
// Copyright (C) 2026 Örjan Lundberg and contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see
// <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package siida.configchain.api

import java.security.MessageDigest
import siida.crypto.api.{MultiSignedEntry, PqSignature, VerifyResult}

/** Append-only governance chain: each entry is a
 *  [[siida.crypto.api.MultiSignedEntry]] (spec 014) whose payload
 *  decodes as a [[ConfigEntry]].
 *
 *  Spec 006-config-chain-governance MVP — in-memory only. Network
 *  distribution + persistent storage are follow-up specs.
 */
trait ConfigChain:

  /** SHA3-256 of the head entry's `MultiSignedEntry` wire bytes.
   *  Empty until [[append]] / [[appendDecoded]] succeeds for the
   *  first entry past genesis (genesis sets it).
   */
  def head: Array[Byte]

  /** Current view: roster + threshold + epoch as of the last
   *  applied entry (initially: the genesis values).
   */
  def currentView: ConfigChain.View

  /** Historical view at the given epoch, if applied. */
  def at(epoch: Long): Option[ConfigChain.View]

  /** All applied entries in epoch order. */
  def history: Seq[MultiSignedEntry.Entry]

  /** Append a signed entry. The entry's payload MUST decode as a
   *  [[ConfigEntry]] chaining from the current head with a
   *  monotonic epoch and ≥ threshold valid signatures from the
   *  CURRENT roster.
   *
   *  Side-effect: on success, the chain head + view advance.
   */
  def append(entry: MultiSignedEntry.Entry): Either[ConfigChainError, ConfigChain.View]


object ConfigChain:

  /** Read-only snapshot of the chain's view at a given epoch. */
  final case class View(
    epoch:     Long,
    roster:    Vector[PqSignature.PqPublicKey],
    threshold: Int,
  )

  /** Establish a fresh chain at epoch 0 with the given roster and
   *  threshold. Genesis is implicitly "self-signed" by the declared
   *  roster — it is the foundation of trust; subsequent entries are
   *  verified against the chain's current view (which starts as
   *  this roster + threshold).
   *
   *  The genesis ConfigEntry is built with the given extension bytes
   *  and prev_hash = all-zero (per FR-003). The genesis MultiSigned
   *  payload IS that ConfigEntry encoded; no signatures are required
   *  on the genesis itself (the roster IS the genesis by construction).
   *  The chain's head becomes SHA3-256 of the genesis payload bytes.
   */
  def genesis(
    roster:              Vector[PqSignature.PqPublicKey],
    threshold:           Int,
    domainSeparationTag: Array[Byte],
    extension:           Array[Byte] = Array.emptyByteArray,
  ): Either[ConfigChainError, ConfigChain] =
    if roster.isEmpty then Left(ConfigChainError.BadRoster("roster must be non-empty"))
    else if threshold < 1 || threshold > roster.length then
      Left(ConfigChainError.BadThreshold(s"threshold $threshold out of [1, ${roster.length}]"))
    else
      val genesisEntry = ConfigEntry(
        epoch = 0L,
        prevHash = ConfigEntry.GenesisPrevHash,
        newRoster = roster,
        newThreshold = threshold,
        extension = extension,
      )
      val payload = ConfigEntry.encode(genesisEntry)
      // No signatures on genesis — the chain's first head IS the
      // hash of the genesis payload. Subsequent entries chain
      // against this hash.
      Right(new InMemoryConfigChain(
        domainSeparationTag = domainSeparationTag.clone(),
        initialView         = View(0L, roster, threshold),
        initialHead         = sha3_256(payload),
        genesisPayload      = payload,
      ))

  /** SHA3-256 over arbitrary bytes — exposed as a public helper so
   *  signing parties can compute `prev_hash` for the next entry.
   */
  def sha3_256(bytes: Array[Byte]): Array[Byte] =
    val md = MessageDigest.getInstance("SHA3-256")
    md.update(bytes)
    md.digest()

  private final class InMemoryConfigChain(
    domainSeparationTag: Array[Byte],
    initialView:         View,
    initialHead:         Array[Byte],
    genesisPayload:      Array[Byte],
  ) extends ConfigChain:

    private var _head: Array[Byte] = initialHead
    private var _view: View        = initialView
    private val _history = scala.collection.mutable.ArrayBuffer.empty[MultiSignedEntry.Entry]
    private val _viewByEpoch = scala.collection.mutable.LinkedHashMap[Long, View](0L -> initialView)
    private val _appliedHashes = scala.collection.mutable.HashSet[scala.collection.immutable.ArraySeq[Byte]](
      scala.collection.immutable.ArraySeq.unsafeWrapArray(initialHead),
    )

    // Synthetic genesis "entry" exposed in history as the
    // unsigned MultiSignedEntry over the genesis payload.
    // This is convenient for downstream consumers (e.g. the SDK)
    // but is NOT verifiable against the chain — it is the chain's
    // foundation of trust.
    locally {
      MultiSignedEntry.assemble(genesisPayload, Seq.empty) match
        case Right(e) => _history += e
        case Left(err) =>
          // Unreachable in practice — empty signatures + small payload
          // always succeed in assemble.
          throw new IllegalStateException(s"genesis assemble failed: $err")
    }

    def head: Array[Byte] = _head.clone()
    def currentView: View = _view
    def at(epoch: Long): Option[View] = _viewByEpoch.get(epoch)
    def history: Seq[MultiSignedEntry.Entry] = _history.toVector

    def append(entry: MultiSignedEntry.Entry): Either[ConfigChainError, View] =
      val entryHash = sha3_256(MultiSignedEntry.serialiseEntry(entry))
      val entryHashKey = scala.collection.immutable.ArraySeq.unsafeWrapArray(entryHash)
      if _appliedHashes.contains(entryHashKey) then
        Left(ConfigChainError.AlreadyApplied)
      else
        appendValidated(entry, entryHash, entryHashKey)

    private def appendValidated(
      entry:        MultiSignedEntry.Entry,
      entryHash:    Array[Byte],
      entryHashKey: scala.collection.immutable.ArraySeq[Byte],
    ): Either[ConfigChainError, View] =
      // 1. Unwrap the entry's payload by re-parsing the wire bytes.
      //    MultiSignedEntry doesn't expose payload extraction directly;
      //    we run verify which both validates the bytes AND
      //    re-derives the payload via the same SHA3 step internally.
      //    For decoded access we parse the wire bytes ourselves.
      val wire = MultiSignedEntry.serialiseEntry(entry)
      payloadFromWire(wire) match
        case Left(err) => Left(err)
        case Right(payload) =>
          ConfigEntry.decode(payload) match
            case Left(err) => Left(err)
            case Right(decoded) =>
              // 2. Chain checks: predecessor + epoch monotonicity +
              //    new roster/threshold sanity.
              if !java.util.Arrays.equals(decoded.prevHash, _head) then
                Left(ConfigChainError.WrongPredecessor)
              else if decoded.epoch != _view.epoch + 1 then
                Left(ConfigChainError.EpochNotMonotonic(_view.epoch + 1, decoded.epoch))
              else if decoded.newRoster.isEmpty then
                Left(ConfigChainError.BadRoster("new roster must be non-empty"))
              else if decoded.newThreshold < 1 || decoded.newThreshold > decoded.newRoster.length then
                Left(ConfigChainError.BadThreshold(
                  s"new_threshold ${decoded.newThreshold} out of [1, ${decoded.newRoster.length}]"))
              else
                // 3. Cryptographic check: ≥ threshold valid signatures
                //    from the CURRENT roster against the entry's payload.
                MultiSignedEntry.verify(_view.roster, _view.threshold, domainSeparationTag, entry) match
                  case VerifyResult.Valid =>
                    _head = entryHash
                    _view = View(decoded.epoch, decoded.newRoster, decoded.newThreshold)
                    _history += entry
                    _viewByEpoch.put(decoded.epoch, _view)
                    _appliedHashes += entryHashKey
                    Right(_view)
                  case VerifyResult.ThresholdNotMet(c, r) =>
                    Left(ConfigChainError.ThresholdNotMet(c, r))
                  case VerifyResult.DuplicateSigner(i) =>
                    Left(ConfigChainError.MalformedEntry(s"duplicate signer index $i"))
                  case VerifyResult.InvalidSignerIndex(i) =>
                    Left(ConfigChainError.MalformedEntry(s"invalid signer index $i"))
                  case VerifyResult.PayloadHashMismatch =>
                    Left(ConfigChainError.MalformedEntry("payload hash mismatch"))
                  case VerifyResult.MalformedEntry(r) =>
                    Left(ConfigChainError.MalformedEntry(r))

    // Re-parse the MultiSignedEntry wire bytes to recover the
    // raw payload. Mirrors the layout pinned in
    // modules/crypto/src/siida/crypto/api/MultiSignedEntry.scala.
    private def payloadFromWire(wire: Array[Byte]): Either[ConfigChainError, Array[Byte]] =
      val HeaderBytes      = 3
      val PqSigWireBytes   = 3310
      val SignerIndexBytes = 2
      val TupleBytes       = SignerIndexBytes + PqSigWireBytes
      val PayloadHashBytes = 32
      if wire.length < HeaderBytes + PayloadHashBytes then
        Left(ConfigChainError.MalformedEntry("entry too short"))
      else
        val n = ((wire(1) & 0xFF) << 8) | (wire(2) & 0xFF)
        val payloadOffset = HeaderBytes + n * TupleBytes + PayloadHashBytes
        if wire.length < payloadOffset then
          Left(ConfigChainError.MalformedEntry("entry shorter than declared signature count"))
        else
          Right(java.util.Arrays.copyOfRange(wire, payloadOffset, wire.length))
