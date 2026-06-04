// SPDX-License-Identifier: AGPL-3.0-or-later

package linecode

import "testing"

// FuzzDecodeManchester asserts the Manchester decoder never panics on an
// arbitrary bit string (odd lengths, non-01 chars, empty).
func FuzzDecodeManchester(f *testing.F) {
	for _, s := range []string{"", "0", "01", "0101010101", "1100", "xyz", "010"} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = DecodeManchester(s) // must not panic
	})
}
