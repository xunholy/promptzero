// SPDX-License-Identifier: AGPL-3.0-or-later

package homepluggp

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		"01646000001122334455667788",
		"016a6000000a0001112233445566aabbccddeeff0011",
		"01086001aaaaaaaabbbbbbbb02000100000102030405060701000102030405060708090a0b0c0d0e0f",
		"017d60000056004556000000000000000000000000000000aabbccddeeff",
		"0150A0",
		"zz",
		"016f60",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
