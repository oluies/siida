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

package siida.crypto.api

import java.security.MessageDigest

/** Multi-signer entry: a payload plus N (signer_index, PqSignature)
 *  tuples, verified as M-of-N against a roster of public keys and a
 *  domain-separation tag.
 *
 *  Spec 014-pq-config-chain-redesign. Spec 006 (config-chain
 *  governance) consumes this for chain entries; spec 015
 *  (identity encryption) consumes it for directory-entry proofs.
 *
 *  ## Wire format (version 0x01)
 *
 *  ```
 *  offset                size      field
 *  0                     1         FormatVersion (0x01)
 *  1                     2         signature count `n` (uint16 BE)
 *  3                     n × 3312  signature tuples: each =
 *                                    2-byte signer_index (uint16 BE) +
 *                                    3310-byte PqSignature wire envelope
 *  3 + n×3312            32        SHA3-256(payload)
 *  3 + n×3312 + 32       *         payload bytes (opaque to 014)
 *  ```
 *
 *  Total: `35 + n × 3312 + |payload|` bytes. The contract doc in
 *  `specs/014/contracts/wire-format.md` lists 3296 bytes per tuple
 *  (3294-byte signature + 2-byte index); the actual size is 3312
 *  because FIPS 204 ML-DSA-65 signatures are 3309 bytes, not 3293
 *  (the design-doc error that 013's implementation corrected).
 *
 *  ## Signed-message construction
 *
 *  Each signer pre-computes:
 *    `signed_message = SHA3-256(payload) || domain_separation_tag`
 *
 *  …and signs that via `PqSignature.sign(sk, signed_message)`. The
 *  verifier re-derives the same signed message and runs each
 *  signature through `PqSignature.verify`. The `signedMessage`
 *  helper exposes the construction for completeness.
 */
object MultiSignedEntry:

  opaque type Entry = Array[Byte]

  /** Wire-format version tag for this spec. */
  val FormatVersion: Byte = 0x01

  // Per-tuple size: 2-byte signer_index (uint16 BE) + 3310-byte
  // PqSignature wire envelope. Note: spec 014's wire-format
  // contract lists 3296 bytes per tuple (assuming 3294-byte
  // signature); the actual size is 3312 because FIPS 204 ML-DSA-65
  // signatures are 3309 bytes (per FIPS 204 Table 1), corrected
  // during 013's implementation.
  private inline val SignerIndexBytes  = 2
  private inline val PqSigWireBytes    = 3310
  private inline val TupleBytes        = SignerIndexBytes + PqSigWireBytes // 3312
  private inline val PayloadHashBytes  = 32
  private inline val HeaderBytes       = 1 + 2 // FormatVersion + n
  private inline val MinEntryBytes     = HeaderBytes + PayloadHashBytes    // empty signatures, empty payload

  // ── Helpers ────────────────────────────────────────────────────

  /** Compute the per-signer signed-message bytes:
   *    SHA3-256(payload) || domain_separation_tag
   *
   *  Exposed so signing parties can pass the exact bytes to
   *  `PqSignature.sign` and so verifiers can construct the same
   *  bytes for `PqSignature.verify`.
   */
  def signedMessage(payload: Array[Byte], domainSeparationTag: Array[Byte]): Array[Byte] =
    val h = sha3_256(payload)
    val out = new Array[Byte](h.length + domainSeparationTag.length)
    System.arraycopy(h, 0, out, 0, h.length)
    System.arraycopy(domainSeparationTag, 0, out, h.length, domainSeparationTag.length)
    out

  private def sha3_256(bytes: Array[Byte]): Array[Byte] =
    val md = MessageDigest.getInstance("SHA3-256")
    md.update(bytes)
    md.digest()

  // ── Construction ───────────────────────────────────────────────

  /** Assemble an entry from a payload and a sequence of pre-computed
   *  signatures. Each signature is paired with its signer_index
   *  (the verifier uses this to look up the signer in the roster).
   *
   *  Returns `Left(InvalidSignatureCount)` if `n > 65535` (the wire
   *  count is uint16). Returns `Left(DuplicateSignerIndex)` if any
   *  signer_index appears twice — the spec rejects duplicates at
   *  verify time too, but catching it at assemble is friendlier.
   */
  def assemble(
    payload:    Array[Byte],
    signatures: Seq[(Int, PqSignature.Signature)],
  ): Either[MultiSignedEntryError, Entry] =
    if signatures.length > 0xFFFF then
      Left(MultiSignedEntryError.InvalidSignatureCount(signatures.length))
    else
      // Validate signer_indices first (range + duplicates).
      val validation = signatures.foldLeft(Right(scala.collection.mutable.HashSet.empty[Int])
        : Either[MultiSignedEntryError, scala.collection.mutable.HashSet[Int]]) { (acc, tup) =>
        acc.flatMap { seen =>
          val idx = tup._1
          if idx < 0 || idx > 0xFFFF then
            Left(MultiSignedEntryError.MalformedBytes(s"signer_index out of range: $idx"))
          else if !seen.add(idx) then
            Left(MultiSignedEntryError.DuplicateSignerIndex(idx))
          else
            Right(seen)
        }
      }
      validation.flatMap { _ =>
        // Validate signature wire sizes.
        val badSig = signatures.iterator.map { case (_, sig) =>
          PqSignature.serialiseSignature(sig).length
        }.find(_ != PqSigWireBytes)
        if badSig.isDefined then
          Left(MultiSignedEntryError.MalformedBytes(
            s"signature wire size ${badSig.get} != $PqSigWireBytes"))
        else
          val n = signatures.length
          val payloadHash = sha3_256(payload)
          val total = HeaderBytes + n * TupleBytes + PayloadHashBytes + payload.length
          val out = new Array[Byte](total)
          out(0) = FormatVersion
          out(1) = ((n >>> 8) & 0xFF).toByte
          out(2) = (n & 0xFF).toByte
          var off = HeaderBytes
          signatures.foreach { case (idx, sig) =>
            out(off)     = ((idx >>> 8) & 0xFF).toByte
            out(off + 1) = (idx & 0xFF).toByte
            val sigBytes = PqSignature.serialiseSignature(sig)
            System.arraycopy(sigBytes, 0, out, off + SignerIndexBytes, PqSigWireBytes)
            off += TupleBytes
          }
          System.arraycopy(payloadHash, 0, out, off, PayloadHashBytes)
          off += PayloadHashBytes
          System.arraycopy(payload, 0, out, off, payload.length)
          Right(out)
      }

  // ── Verify ────────────────────────────────────────────────────

  /** Verify an entry against a roster of public keys, a threshold,
   *  and a domain-separation tag. See research R5 / wire-format
   *  contract for the algorithm.
   */
  def verify(
    roster:              Seq[PqSignature.PqPublicKey],
    threshold:           Int,
    domainSeparationTag: Array[Byte],
    entry:               Entry,
  ): VerifyResult =
    if entry.length < MinEntryBytes then
      VerifyResult.MalformedEntry(s"entry too short: ${entry.length}")
    else if entry(0) != FormatVersion then
      VerifyResult.MalformedEntry("unsupported version")
    else
      val n = ((entry(1) & 0xFF) << 8) | (entry(2) & 0xFF)
      val expectedFixed = HeaderBytes + n * TupleBytes + PayloadHashBytes
      if entry.length < expectedFixed then
        VerifyResult.MalformedEntry("entry shorter than declared signature count")
      else
        verifyParsed(roster, threshold, domainSeparationTag, entry, n)

  /** Continuation of [[verify]] after the prelude size checks. Split
   *  out to keep the early-return chain small and avoid non-local
   *  returns (deprecated in Scala 3).
   */
  private def verifyParsed(
    roster:              Seq[PqSignature.PqPublicKey],
    threshold:           Int,
    domainSeparationTag: Array[Byte],
    entry:               Array[Byte],
    n:                   Int,
  ): VerifyResult =
    // 1. Slice out signatures, payload hash, payload — short-circuit
    //    via a sentinel rather than non-local return.
    var off = HeaderBytes
    val signatures = scala.collection.mutable.ArrayBuffer.empty[(Int, Array[Byte])]
    val seen       = scala.collection.mutable.HashSet.empty[Int]
    var dupResult: VerifyResult = null
    var i = 0
    while i < n && dupResult == null do
      val idx = ((entry(off) & 0xFF) << 8) | (entry(off + 1) & 0xFF)
      if !seen.add(idx) then
        dupResult = VerifyResult.DuplicateSigner(idx)
      else
        val sigBytes = java.util.Arrays.copyOfRange(entry, off + SignerIndexBytes, off + TupleBytes)
        signatures += ((idx, sigBytes))
        off += TupleBytes
        i += 1
    if dupResult != null then return dupResult

    val recordedHash = java.util.Arrays.copyOfRange(entry, off, off + PayloadHashBytes)
    off += PayloadHashBytes
    val payload = java.util.Arrays.copyOfRange(entry, off, entry.length)

    // 2. Re-hash the payload and compare
    val actualHash = sha3_256(payload)
    if !java.util.Arrays.equals(actualHash, recordedHash) then
      return VerifyResult.PayloadHashMismatch

    // 3. Build the signed-message bytes (same for all signers)
    val msg = signedMessage(payload, domainSeparationTag)

    // 4. Per-tuple: bounds-check signer_index; deserialise PqSignature.
    //    Use an explicit while-loop so an out-of-range index short-
    //    circuits cleanly without non-local return (deprecated in
    //    Scala 3).
    val typed = scala.collection.mutable.ArrayBuffer.empty[(PqSignature.PqPublicKey, Array[Byte], PqSignature.Signature)]
    var sigIdx = 0
    var oobResult: VerifyResult = null
    while sigIdx < signatures.length && oobResult == null do
      val (idx, sigBytes) = signatures(sigIdx)
      if idx < 0 || idx >= roster.length then
        oobResult = VerifyResult.InvalidSignerIndex(idx)
      else
        PqSignature.deserialiseSignature(sigBytes) match
          case Right(sig) => typed += ((roster(idx), msg, sig))
          case Left(_)    =>
            // Wire-level malformed signature — treat as invalid and
            // fall through to count-based ThresholdNotMet rather than
            // hard-failing. The count of valid sigs goes down by one.
            ()
      sigIdx += 1
    if oobResult != null then return oobResult

    // 5. Batch-verify; if every tuple verified, we're done.
    val allValid = typed.length == signatures.length && PqSignature.batchVerify(typed.toSeq)
    val validCount = if allValid then typed.length
                     else typed.count((pk, m, s) => PqSignature.verify(pk, m, s))

    if validCount < threshold then
      VerifyResult.ThresholdNotMet(validCount, threshold)
    else
      VerifyResult.Valid

  // ── Serialisation ─────────────────────────────────────────────

  def serialiseEntry(entry: Entry): Array[Byte] = entry.clone()

  def deserialiseEntry(bytes: Array[Byte]): Either[MultiSignedEntryError, Entry] =
    if bytes.length < MinEntryBytes then Left(MultiSignedEntryError.InvalidLength)
    else if bytes(0) != FormatVersion then Left(MultiSignedEntryError.UnsupportedVersion)
    else
      val n = ((bytes(1) & 0xFF) << 8) | (bytes(2) & 0xFF)
      val expectedFixed = HeaderBytes + n * TupleBytes + PayloadHashBytes
      if bytes.length < expectedFixed then
        Left(MultiSignedEntryError.MalformedBytes("entry shorter than declared signature count"))
      else
        Right(bytes.clone())

  // ── Helpers exposed for testing & coordination ──────────────────

  /** Per-tuple wire size, including the 2-byte signer_index prefix
   *  and the 3310-byte PqSignature envelope. Exposed so callers (e.g.,
   *  spec 006's chain-construction code) can size buffers correctly.
   */
  val TupleWireBytes: Int = TupleBytes
