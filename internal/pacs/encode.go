// SPDX-License-Identifier: AGPL-3.0-or-later

package pacs

import (
	"fmt"
	"strings"
)

// EncodeWiegand builds the raw Wiegand bit-string for a named HID format
// from a facility code + card number — the inverse of DecodeBits. The
// result is the exact frame DecodeBits parses back (round-trip verified):
// leading even-parity bit, the BCD-less binary FC + CN fields, and the
// trailing odd-parity bit, MSB-first.
//
// # Wrap-vs-native judgement
//
// Native, and the inverse of the existing decoder. HID Wiegand formats are
// public, fixed-width bit layouts with parity — pure bit-twiddling, no
// crypto, no state, no hardware. Generation only: this produces the bits an
// operator would write to a T5577/emulate; it performs no write or TX, so
// it carries the same Low risk as the decoder. Correctness is verifiable
// three ways: round-trip against DecodeBits, hand-computed parity vectors,
// and the published HID format layouts.
//
// # Covered formats (clean, non-overlapping parity — hand-verifiable)
//
//   - "H10301" — 26-bit: even parity + 8-bit FC + 16-bit CN + odd parity.
//     Even parity over the top 12 data bits, odd over the bottom 12.
//   - "H10306" — 34-bit: even parity + 16-bit FC + 16-bit CN + odd parity.
//     Even parity over the FC, odd over the CN.
//
// # Deliberately deferred
//
// The 37-bit (H10304/H10302) and Corporate 1000 (35/48-bit) formats have
// overlapping / proprietary parity ranges that the decoder treats as
// best-effort. Encoding them without an external reference vector risks a
// confidently-wrong frame, so they are not offered here (decode still
// surfaces them as candidates).
func EncodeWiegand(format string, facilityCode, cardNumber uint64) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(format)) {
	case "H10301", "H10301 26-BIT", "26":
		return encodeStandard(facilityCode, cardNumber, 8, 16, "H10301")
	case "H10306", "H10306 34-BIT", "34":
		return encodeStandard(facilityCode, cardNumber, 16, 16, "H10306")
	default:
		return "", fmt.Errorf("pacs: unsupported encode format %q (supported: H10301 (26-bit), H10306 (34-bit))", format)
	}
}

// encodeStandard builds a "[Pe][FC:fcBits][CN:cnBits][Po]" Wiegand frame:
// the leading bit is even parity over the top half of the data field, the
// trailing bit is odd parity over the bottom half — matching decodeH10301 /
// decodeH10306. For H10301 the top half is the 8-bit FC + the top 4 CN
// bits (12 bits); for H10306 it is the full 16-bit FC.
func encodeStandard(fc, cn uint64, fcBits, cnBits int, name string) (string, error) {
	if maxFor(fcBits) < fc {
		return "", fmt.Errorf("pacs %s: facility code %d does not fit in %d bits (max %d)", name, fc, fcBits, maxFor(fcBits))
	}
	if maxFor(cnBits) < cn {
		return "", fmt.Errorf("pacs %s: card number %d does not fit in %d bits (max %d)", name, cn, cnBits, maxFor(cnBits))
	}
	data := uintToBits(fc, fcBits) + uintToBits(cn, cnBits) // 24 (H10301) or 32 (H10306) data bits
	half := len(data) / 2
	leading := parityEven(data[:half]) // even parity over the top half
	trailing := parityOdd(data[half:]) // odd parity over the bottom half
	return fmt.Sprintf("%d%s%d", leading, data, trailing), nil
}

// uintToBits renders v as an n-bit MSB-first binary string.
func uintToBits(v uint64, n int) string {
	var b strings.Builder
	b.Grow(n)
	for i := n - 1; i >= 0; i-- {
		if v&(1<<uint(i)) != 0 {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
	}
	return b.String()
}

// maxFor returns the largest unsigned value representable in n bits.
func maxFor(n int) uint64 {
	if n >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(n)) - 1
}
