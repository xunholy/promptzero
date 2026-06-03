// SPDX-License-Identifier: AGPL-3.0-or-later

package ciscopw

import "testing"

// FuzzDecodeType7 asserts the Cisco type-7 decoder never panics on arbitrary
// input (it parses an untrusted salt-index + hex string from config loot).
func FuzzDecodeType7(f *testing.F) {
	seeds := []string{
		"02050D480809", "060506324F41", "", "0", "99", "1234567890ABCDEF",
		"ZZ", "0Z", "153", "0815", "7e", "00",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, enc string) {
		_, _ = DecodeType7(enc) // must not panic (out-of-range salt index, odd hex, etc.)
	})
}
