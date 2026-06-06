// SPDX-License-Identifier: AGPL-3.0-or-later

package tcl

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		"0200a4040000",
		"130011",
		"0a0c00a4",
		"065100a4",
		"a2", "b3", "aa00", "c2", "f205", "42",
		"zz",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
