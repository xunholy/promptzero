// SPDX-License-Identifier: AGPL-3.0-or-later

package sv

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		oneASDU,
		"40000000000000006046800101a241",
		"40000010000000006102800101",
		"4000000a00000000",
		"zz",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
