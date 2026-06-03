// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

import "testing"

func FuzzDecodeHex(f *testing.F) {
	f.Add("3074257BF7194E4000001A85")
	f.Add("310000000000000000000000")
	f.Add("FF0000000000000000000000")
	f.Add("3074")
	f.Add("")
	f.Add("zz")
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input.
		_, _ = DecodeHex(s)
	})
}
