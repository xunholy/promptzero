// SPDX-License-Identifier: AGPL-3.0-or-later

package hidreport

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		bootKeyboard,
		"05010902a101c0",
		"75089506",
		"050126ff",
		"fe020042",
		"zz",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
