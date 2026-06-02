// SPDX-License-Identifier: AGPL-3.0-or-later

package pacs

import "testing"

// FuzzDecodeBits exercises the multi-format Wiegand decoder on arbitrary
// bit-strings — the per-format field slicing and parity ranges must never
// index out of range regardless of length or content.
func FuzzDecodeBits(f *testing.F) {
	seeds := []string{
		"",
		"10000000100000000000000001",            // 26-bit H10301
		"0000000000000000000000000000000001",    // 34-bit
		"0000000000000000000000000000000000001", // 37-bit
		"00000000000000000000000000000000001",   // 35-bit
		"000000000000000000000000000000000000000000000001", // 48-bit
		"101",
		"2",
		"11111111111111111111111111",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeBits(s) })
}
