// Siida native pairing shim — wraps gnark-crypto BN254 primitives
// behind the C ABI documented in
// specs/002-crypto-pairing/contracts/native-abi.md.
//
// Built as a c-shared library by build.sh:
//   CGO_ENABLED=1 go build -buildmode=c-shared -o libsiida_bn254.<ext>
//
// Copyright (C) 2026 Örjan Lundberg and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// gnark-crypto is Apache-2.0; see ../../../NOTICE for full attribution.

package main

/*
#include <stdint.h>
#include <string.h>
*/
import "C"

import (
	"math/big"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// main is required for c-shared but is never invoked.
func main() {}

// Return-code constants. Keep in lockstep with the SIIDA_OK / SIIDA_ERR_*
// macros in contracts/native-abi.md.
const (
	siidaOK                = 0
	siidaErrInvalidEncoding = -1
	siidaErrNotOnCurve     = -2
	siidaErrNotInSubgroup  = -3
	siidaErrInvalidLength  = -4
	siidaErrInternal       = -99
)

// ───────────────────────────────────────────────────────────────────
// Lifecycle
// ───────────────────────────────────────────────────────────────────

//export siida_bn254_init
func siida_bn254_init() C.int {
	// gnark-crypto initialises its precomputed tables lazily on first
	// use; nothing to do here. The init hook exists so the Scala
	// NativeLoader has a callable function to confirm the library is
	// loaded and reachable.
	return siidaOK
}

// ───────────────────────────────────────────────────────────────────
// Generators
// ───────────────────────────────────────────────────────────────────

//export siida_bn254_g1_generator
func siida_bn254_g1_generator(out *C.uint8_t) {
	_, _, g1, _ := bn254.Generators()
	b := g1.Bytes()
	C.memcpy(unsafe.Pointer(out), unsafe.Pointer(&b[0]), 32)
}

//export siida_bn254_g2_generator
func siida_bn254_g2_generator(out *C.uint8_t) {
	_, _, _, g2 := bn254.Generators()
	b := g2.Bytes()
	C.memcpy(unsafe.Pointer(out), unsafe.Pointer(&b[0]), 64)
}

// ───────────────────────────────────────────────────────────────────
// Scalar mul
// ───────────────────────────────────────────────────────────────────

//export siida_bn254_g1_scalar_mul
func siida_bn254_g1_scalar_mul(scalar *C.uint8_t, point *C.uint8_t, out *C.uint8_t) C.int {
	scalarSlice := C.GoBytes(unsafe.Pointer(scalar), 32)
	pointSlice := C.GoBytes(unsafe.Pointer(point), 32)

	var p bn254.G1Affine
	if _, err := p.SetBytes(pointSlice); err != nil {
		return siidaErrNotOnCurve
	}
	if !p.IsInSubGroup() {
		return siidaErrNotInSubgroup
	}

	s := new(big.Int).SetBytes(scalarSlice)
	var result bn254.G1Affine
	result.ScalarMultiplication(&p, s)

	b := result.Bytes()
	C.memcpy(unsafe.Pointer(out), unsafe.Pointer(&b[0]), 32)
	return siidaOK
}

//export siida_bn254_g2_scalar_mul
func siida_bn254_g2_scalar_mul(scalar *C.uint8_t, point *C.uint8_t, out *C.uint8_t) C.int {
	scalarSlice := C.GoBytes(unsafe.Pointer(scalar), 32)
	pointSlice := C.GoBytes(unsafe.Pointer(point), 64)

	var p bn254.G2Affine
	if _, err := p.SetBytes(pointSlice); err != nil {
		return siidaErrNotOnCurve
	}
	if !p.IsInSubGroup() {
		return siidaErrNotInSubgroup
	}

	s := new(big.Int).SetBytes(scalarSlice)
	var result bn254.G2Affine
	result.ScalarMultiplication(&p, s)

	b := result.Bytes()
	C.memcpy(unsafe.Pointer(out), unsafe.Pointer(&b[0]), 64)
	return siidaOK
}

// ───────────────────────────────────────────────────────────────────
// Add
// ───────────────────────────────────────────────────────────────────

//export siida_bn254_g1_add
func siida_bn254_g1_add(p *C.uint8_t, q *C.uint8_t, out *C.uint8_t) C.int {
	pSlice := C.GoBytes(unsafe.Pointer(p), 32)
	qSlice := C.GoBytes(unsafe.Pointer(q), 32)

	var a bn254.G1Affine
	if _, err := a.SetBytes(pSlice); err != nil {
		return siidaErrNotOnCurve
	}
	if !a.IsInSubGroup() {
		return siidaErrNotInSubgroup
	}

	var b bn254.G1Affine
	if _, err := b.SetBytes(qSlice); err != nil {
		return siidaErrNotOnCurve
	}
	if !b.IsInSubGroup() {
		return siidaErrNotInSubgroup
	}

	var result bn254.G1Affine
	result.Add(&a, &b)

	rb := result.Bytes()
	C.memcpy(unsafe.Pointer(out), unsafe.Pointer(&rb[0]), 32)
	return siidaOK
}

//export siida_bn254_g2_add
func siida_bn254_g2_add(p *C.uint8_t, q *C.uint8_t, out *C.uint8_t) C.int {
	pSlice := C.GoBytes(unsafe.Pointer(p), 64)
	qSlice := C.GoBytes(unsafe.Pointer(q), 64)

	var a bn254.G2Affine
	if _, err := a.SetBytes(pSlice); err != nil {
		return siidaErrNotOnCurve
	}
	if !a.IsInSubGroup() {
		return siidaErrNotInSubgroup
	}

	var b bn254.G2Affine
	if _, err := b.SetBytes(qSlice); err != nil {
		return siidaErrNotOnCurve
	}
	if !b.IsInSubGroup() {
		return siidaErrNotInSubgroup
	}

	var result bn254.G2Affine
	result.Add(&a, &b)

	rb := result.Bytes()
	C.memcpy(unsafe.Pointer(out), unsafe.Pointer(&rb[0]), 64)
	return siidaOK
}

// ───────────────────────────────────────────────────────────────────
// Pairings
// ───────────────────────────────────────────────────────────────────

//export siida_bn254_pairing
func siida_bn254_pairing(g1 *C.uint8_t, g2 *C.uint8_t, out *C.uint8_t) C.int {
	g1Slice := C.GoBytes(unsafe.Pointer(g1), 32)
	g2Slice := C.GoBytes(unsafe.Pointer(g2), 64)

	var p bn254.G1Affine
	if _, err := p.SetBytes(g1Slice); err != nil {
		return siidaErrNotOnCurve
	}
	if !p.IsInSubGroup() {
		return siidaErrNotInSubgroup
	}

	var q bn254.G2Affine
	if _, err := q.SetBytes(g2Slice); err != nil {
		return siidaErrNotOnCurve
	}
	if !q.IsInSubGroup() {
		return siidaErrNotInSubgroup
	}

	res, err := bn254.Pair([]bn254.G1Affine{p}, []bn254.G2Affine{q})
	if err != nil {
		return siidaErrInternal
	}

	rb := res.Marshal() // 384 bytes
	if len(rb) != 384 {
		return siidaErrInternal
	}
	C.memcpy(unsafe.Pointer(out), unsafe.Pointer(&rb[0]), 384)
	return siidaOK
}

// siida_bn254_pairing_check returns:
//   0  if ∏ e(g1[i], g2[i]) == 1 (the check holds)
//   1  if the check does not hold (legitimate False; NOT an error)
//  <0  on encoding error (out-of-band)
//
//export siida_bn254_pairing_check
func siida_bn254_pairing_check(g1s *C.uint8_t, g2s *C.uint8_t, n C.size_t) C.int {
	count := int(n)
	if count <= 0 {
		return siidaErrInvalidLength
	}

	g1Slice := C.GoBytes(unsafe.Pointer(g1s), C.int(count*32))
	g2Slice := C.GoBytes(unsafe.Pointer(g2s), C.int(count*64))

	g1Points := make([]bn254.G1Affine, count)
	g2Points := make([]bn254.G2Affine, count)

	for i := 0; i < count; i++ {
		if _, err := g1Points[i].SetBytes(g1Slice[i*32 : (i+1)*32]); err != nil {
			return siidaErrNotOnCurve
		}
		if !g1Points[i].IsInSubGroup() {
			return siidaErrNotInSubgroup
		}
		if _, err := g2Points[i].SetBytes(g2Slice[i*64 : (i+1)*64]); err != nil {
			return siidaErrNotOnCurve
		}
		if !g2Points[i].IsInSubGroup() {
			return siidaErrNotInSubgroup
		}
	}

	ok, err := bn254.PairingCheck(g1Points, g2Points)
	if err != nil {
		return siidaErrInternal
	}
	if ok {
		return 0
	}
	return 1
}

// ───────────────────────────────────────────────────────────────────
// Hash to curve
// ───────────────────────────────────────────────────────────────────

//export siida_bn254_g2_hash_to_curve
func siida_bn254_g2_hash_to_curve(
	msg *C.uint8_t, msgLen C.size_t,
	dst *C.uint8_t, dstLen C.size_t,
	out *C.uint8_t,
) C.int {
	msgSlice := C.GoBytes(unsafe.Pointer(msg), C.int(msgLen))
	dstSlice := C.GoBytes(unsafe.Pointer(dst), C.int(dstLen))

	g2, err := bn254.HashToG2(msgSlice, dstSlice)
	if err != nil {
		return siidaErrInternal
	}

	b := g2.Bytes()
	C.memcpy(unsafe.Pointer(out), unsafe.Pointer(&b[0]), 64)
	return siidaOK
}

// ───────────────────────────────────────────────────────────────────
// Subgroup checks
// ───────────────────────────────────────────────────────────────────

//export siida_bn254_g1_subgroup_check
func siida_bn254_g1_subgroup_check(point *C.uint8_t) C.int {
	pSlice := C.GoBytes(unsafe.Pointer(point), 32)

	var p bn254.G1Affine
	if _, err := p.SetBytes(pSlice); err != nil {
		return siidaErrNotOnCurve
	}
	if !p.IsInSubGroup() {
		return siidaErrNotInSubgroup
	}
	return siidaOK
}

//export siida_bn254_g2_subgroup_check
func siida_bn254_g2_subgroup_check(point *C.uint8_t) C.int {
	pSlice := C.GoBytes(unsafe.Pointer(point), 64)

	var p bn254.G2Affine
	if _, err := p.SetBytes(pSlice); err != nil {
		return siidaErrNotOnCurve
	}
	if !p.IsInSubGroup() {
		return siidaErrNotInSubgroup
	}
	return siidaOK
}

// ───────────────────────────────────────────────────────────────────
// Scalar utility
// ───────────────────────────────────────────────────────────────────

//export siida_bn254_scalar_reduce
func siida_bn254_scalar_reduce(in *C.uint8_t, out *C.uint8_t) {
	src := C.GoBytes(unsafe.Pointer(in), 32)

	s := new(big.Int).SetBytes(src)
	// bn254 scalar field order r.
	r := bn254.ID.ScalarField()
	s.Mod(s, r)

	// Write back as 32-byte big-endian, zero-padded on the left.
	b := s.Bytes()
	out32 := make([]byte, 32)
	copy(out32[32-len(b):], b)
	C.memcpy(unsafe.Pointer(out), unsafe.Pointer(&out32[0]), 32)
}
