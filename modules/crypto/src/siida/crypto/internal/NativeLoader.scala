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

package siida.crypto.internal

import java.io.InputStream
import java.nio.file.{Files, Path, StandardCopyOption}
import siida.crypto.api.UnsupportedNativeArchException

/** Locates and loads the per-architecture native BN254 shim
 *  (`libsiida_bn254.{so,dylib}`) at JVM startup.
 *
 *  Algorithm:
 *  1. Compute the target triple from `os.name` + `os.arch`
 *     system properties.
 *  2. Open the matching binary from the classpath at
 *     `/native/<triple>/libsiida_bn254.<ext>`.
 *  3. Extract it to a temp file with the correct suffix so the
 *     OS loader recognises it as a shared library.
 *  4. Return the absolute path so JNA can `load` it directly.
 *
 *  Failures throw `UnsupportedNativeArchException` — this is a
 *  programming-environment failure, not a per-call error, so it
 *  follows the constitution-blessed "exceptions for programming
 *  errors and resource failures" carve-out in FR-005.
 */
object NativeLoader:

  /** Resolved at first use. Throws on any unsupported arch /
   *  missing binary; subsequent calls return the cached path.
   */
  lazy val libraryPath: String = extractAndResolve()

  /** The library base name (without `lib` prefix or extension) that
   *  JNA's `Native.load(name, iface)` expects.
   */
  val libraryName: String = "siida_bn254"

  private def extractAndResolve(): String =
    val triple = detectTriple()
    val ext = detectExtension(triple)
    // Mill mounts modules/crypto/native/'s *contents* at the classpath
    // root, so the binary is reachable as /<triple>/libsiida_bn254.<ext>
    // — no leading /native/ segment.
    val resourcePath = s"/$triple/libsiida_bn254.$ext"

    val in: InputStream =
      Option(getClass.getResourceAsStream(resourcePath)).getOrElse {
        throw UnsupportedNativeArchException(
          s"Siida native shim not packaged for triple '$triple' " +
            s"(looked for $resourcePath on the classpath). " +
            "Build with the matrix CI job or rebuild locally via " +
            "modules/crypto/native/build.sh."
        )
      }

    try
      val tmpDir = Files.createTempDirectory("siida-native-")
      val tmpFile: Path = tmpDir.resolve(s"libsiida_bn254.$ext")
      Files.copy(in, tmpFile, StandardCopyOption.REPLACE_EXISTING)
      tmpFile.toFile.deleteOnExit()
      tmpDir.toFile.deleteOnExit()
      tmpFile.toAbsolutePath.toString
    finally in.close()

  private def detectTriple(): String =
    val osName = sys.props.getOrElse("os.name", "").toLowerCase
    val osArch = sys.props.getOrElse("os.arch", "").toLowerCase

    val os =
      if osName.contains("mac") || osName.contains("darwin") then "darwin"
      else if osName.contains("linux") then "linux"
      else
        throw UnsupportedNativeArchException(
          s"Unsupported OS '$osName'. Supported: linux, darwin."
        )

    val arch = osArch match
      case "amd64" | "x86_64"  => "amd64"
      case "arm64" | "aarch64" => "arm64"
      case other =>
        throw UnsupportedNativeArchException(
          s"Unsupported arch '$other'. Supported: amd64, arm64."
        )

    s"$os-$arch"

  private def detectExtension(triple: String): String =
    if triple.startsWith("darwin-") then "dylib"
    else if triple.startsWith("linux-") then "so"
    else
      throw UnsupportedNativeArchException(
        s"Don't know the shared-library extension for triple '$triple'"
      )
