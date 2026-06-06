// SPDX-License-Identifier: AGPL-3.0-or-later

package esmc

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		"0a0019a700011000000001000402",
		"0a0019a70001180000000100040f",
		"010019a7000110000000",
		"0a0019a70001100000000000",
		"zz",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
