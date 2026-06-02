// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nthash computes the Windows NT hash (NTLM) of a password: the
// MD4 digest of the password encoded as little-endian UTF-16. It is the
// compute side of the credential toolkit — hash_identify recognises an NTLM
// hash and hash_crack attacks one, but neither can produce one. Computing an
// NT hash from a known or candidate password is the everyday primitive for
// confirming a cracked password, preparing a pass-the-hash value, or building
// test data. Pure offline compute from an operator-supplied string; no network
// or device interaction.
//
// # Wrap-vs-native judgement
//
// Native. The NT hash is MD4(UTF-16LE(password)). MD4 (RFC 1320) is absent from
// the Go standard library (it is deprecated) and is otherwise only available
// from golang.org/x/crypto/md4 — itself a discouraged package. Rather than take
// that dependency, MD4 is implemented here directly (it is ~50 lines of the
// three RFC 1320 rounds), keeping the primitive owned in-tree and consistent
// with internal/otp, internal/hmacutil, internal/jwtsig and internal/wpa.
//
// # Verifiable / no confidently-wrong output
//
// Strong verification class. MD4 is gated against the complete RFC 1320
// Appendix A.5 test suite (MD4("") = 31d6cfe0…, MD4("abc") = a448017a…, the full
// seven-vector set), and NTHash against the universally published NTLM vector
// (NTHash("password") = 8846f7eaee8fb117ad06bdd830b7586c). The hash ships only
// if it reproduces every published vector, so no external oracle is needed.
//
// # Covered / deferred
//
// Covered: the NT (NTLM) hash for any Unicode password (encoded UTF-16LE per the
// Windows convention). Deferred: the legacy LM hash (DES-based, uppercased,
// 14-character truncated) — held back until it can be gated against a
// confidently-sourced non-trivial vector, since a wrong hash is worse than none.
package nthash

import (
	"encoding/binary"
	"math/bits"
	"unicode/utf16"
)

// MD4 returns the 16-byte RFC 1320 MD4 digest of data.
func MD4(data []byte) []byte {
	// Work on a copy so the caller's slice is never mutated by padding.
	msg := make([]byte, len(data))
	copy(msg, data)

	a, b, c, d := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)

	// Pad: 0x80, zeros to 56 mod 64, then the 64-bit little-endian bit length.
	bitLen := uint64(len(msg)) * 8
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0x00)
	}
	msg = binary.LittleEndian.AppendUint64(msg, bitLen)

	f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	h := func(x, y, z uint32) uint32 { return x ^ y ^ z }

	round1 := []struct{ k, s int }{
		{0, 3}, {1, 7}, {2, 11}, {3, 19}, {4, 3}, {5, 7}, {6, 11}, {7, 19},
		{8, 3}, {9, 7}, {10, 11}, {11, 19}, {12, 3}, {13, 7}, {14, 11}, {15, 19},
	}
	round2 := []struct{ k, s int }{
		{0, 3}, {4, 5}, {8, 9}, {12, 13}, {1, 3}, {5, 5}, {9, 9}, {13, 13},
		{2, 3}, {6, 5}, {10, 9}, {14, 13}, {3, 3}, {7, 5}, {11, 9}, {15, 13},
	}
	round3 := []struct{ k, s int }{
		{0, 3}, {8, 9}, {4, 11}, {12, 15}, {2, 3}, {10, 9}, {6, 11}, {14, 15},
		{1, 3}, {9, 9}, {5, 11}, {13, 15}, {3, 3}, {11, 9}, {7, 11}, {15, 15},
	}

	var x [16]uint32
	for i := 0; i < len(msg); i += 64 {
		for j := range x {
			x[j] = binary.LittleEndian.Uint32(msg[i+4*j:])
		}
		aa, bb, cc, dd := a, b, c, d
		for _, r := range round1 {
			a = bits.RotateLeft32(a+f(b, c, d)+x[r.k], r.s)
			a, b, c, d = d, a, b, c
		}
		for _, r := range round2 {
			a = bits.RotateLeft32(a+g(b, c, d)+x[r.k]+0x5a827999, r.s)
			a, b, c, d = d, a, b, c
		}
		for _, r := range round3 {
			a = bits.RotateLeft32(a+h(b, c, d)+x[r.k]+0x6ed9eba1, r.s)
			a, b, c, d = d, a, b, c
		}
		a, b, c, d = a+aa, b+bb, c+cc, d+dd
	}

	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:], a)
	binary.LittleEndian.PutUint32(out[4:], b)
	binary.LittleEndian.PutUint32(out[8:], c)
	binary.LittleEndian.PutUint32(out[12:], d)
	return out
}

// NTHash returns the 16-byte Windows NT (NTLM) hash of password: the MD4 digest
// of the password encoded as little-endian UTF-16, per the Windows convention.
func NTHash(password string) []byte {
	units := utf16.Encode([]rune(password))
	b := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[i*2:], u)
	}
	return MD4(b)
}
