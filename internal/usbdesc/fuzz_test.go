// SPDX-License-Identifier: AGPL-3.0-or-later

package usbdesc

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		"12010002000000406a049f88000101020301",
		"09021900010100a032090400000103010100" + "0705810308000a",
		"060348006900",
		"ff01dead",
		"zz",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
