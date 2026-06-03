// SPDX-License-Identifier: AGPL-3.0-or-later

package wsc

import "testing"

func FuzzDecodeHex(f *testing.F) {
	f.Add("100e0033104500094d794e6574776f726b10030002002010" +
		"0f000200081027000c537570337253656372657421102000060011223344 55")
	f.Add("104a000110")
	f.Add("1018000400112233")
	f.Add("104500ffaabb")
	f.Add("")
	f.Add("zz")
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input.
		_, _ = DecodeHex(s)
	})
}
