// SPDX-License-Identifier: AGPL-3.0-or-later

package felica

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		"0600ffff0100",
		"14010101010101010101010398887766554412fc",
		"1d070102030405060708000001aabbccddeeff00112233445566778899",
		"0f0d010203040506070802 12fc88b4",
		"02fe",
		"zz",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
