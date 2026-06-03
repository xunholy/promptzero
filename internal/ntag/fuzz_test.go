// SPDX-License-Identifier: AGPL-3.0-or-later

package ntag

import "testing"

func FuzzDecodeHex(f *testing.F) {
	f.Add("0400 00FF 00000000")
	f.Add("00000004 80000000")
	f.Add("04 00 00 FF 00 00 00 00 FFFFFFFF 0000 0000")
	f.Add("0011")
	f.Add("")
	f.Add("zz")
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input.
		_, _ = DecodeHex(s)
	})
}
