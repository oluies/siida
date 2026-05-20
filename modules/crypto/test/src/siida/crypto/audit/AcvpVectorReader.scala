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

package siida.crypto.audit

import scala.io.Source

/** Read a NIST ACVP `internalProjection.json` vector file from the
 *  test classpath, returning typed test cases for the audit suites.
 *
 *  The ACVP schema we consume:
 *
 *  ```
 *  {
 *    "vsId": 42,
 *    "algorithm": "ML-KEM",
 *    "mode": "keyGen",
 *    "revision": "FIPS203",
 *    "testGroups": [{
 *      "tgId": 2,
 *      "testType": "AFT",
 *      "parameterSet": "ML-KEM-768",
 *      "tests": [{
 *        "tcId": 1,
 *        "z": "...hex...",
 *        "d": "...hex...",
 *        "ek": "...hex...",    // expected encapsulation key
 *        "dk": "...hex..."     // expected decapsulation key
 *      }, ...]
 *    }]
 *  }
 *  ```
 *
 *  We only need a tiny subset of fields; the reader exposes a thin
 *  facade over the parsed JSON.
 */
object AcvpVectorReader:

  final case class TestGroup(
    tgId:          Int,
    parameterSet:  String,
    testType:      String,
    tests:         Vector[JsonValue.JObj],
  )

  final case class VectorFile(
    algorithm:   String,
    mode:        String,
    revision:    String,
    testGroups:  Vector[TestGroup],
  )

  /** Load an ACVP vector file from the test classpath under
   *  `/acvp/<filename>`.
   */
  def load(resourcePath: String): VectorFile =
    val url = Option(getClass.getResource(resourcePath))
      .getOrElse(throw RuntimeException(s"ACVP vector file not on classpath: $resourcePath"))
    val src = Source.fromURL(url, "UTF-8")
    val raw =
      try src.getLines().mkString("\n")
      finally src.close()
    val root = JsonValue.parse(raw)
    val algorithm = root.field("algorithm").asString
    val mode      = root.field("mode").asString
    val revision  = root.field("revision").asString
    val tgs = root.field("testGroups").asArr.map: tg =>
      TestGroup(
        tgId         = tg.field("tgId").asLong.toInt,
        parameterSet = tg.field("parameterSet").asString,
        testType     = tg.field("testType").asString,
        tests        = tg.field("tests").asArr.map(_.asInstanceOf[JsonValue.JObj]),
      )
    VectorFile(algorithm, mode, revision, tgs)

  /** Decode a hex string (any case) to bytes. */
  def hex(s: String): Array[Byte] =
    require(s.length % 2 == 0, s"hex string has odd length: ${s.length}")
    val out = new Array[Byte](s.length / 2)
    var i = 0
    while i < out.length do
      out(i) = ((Character.digit(s.charAt(i * 2), 16) << 4) | Character.digit(s.charAt(i * 2 + 1), 16)).toByte
      i += 1
    out

  /** Hex-encode bytes (lowercase, no separator). For error messages. */
  def hex(bytes: Array[Byte]): String =
    val sb = new StringBuilder(bytes.length * 2)
    bytes.foreach: b =>
      sb.append("%02x".format(b & 0xff))
    sb.toString

  /** A short prefix of a hex-encoded byte array, for log readability. */
  def hexShort(bytes: Array[Byte], n: Int = 16): String =
    val full = hex(bytes)
    if full.length <= n * 2 then full
    else full.take(n * 2) + s"…(${bytes.length} bytes total)"
