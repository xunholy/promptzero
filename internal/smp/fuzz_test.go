// SPDX-License-Identifier: AGPL-3.0-or-later

package smp

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{"", "0104000d100707", "01030001100000", "0503", "0b0d", "0900ffeeddccbbaa", "06000102030405060708090a0b0c0d0e0f", "zz"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
