// SPDX-License-Identifier: AGPL-3.0-or-later

package pmbus

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{"", "8830f0", "8d1900", "21cd0c", "0180", "7824", "790080", "8cf007", "c5", "zz"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
