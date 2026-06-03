// SPDX-License-Identifier: AGPL-3.0-or-later

package t55xx

import "testing"

func FuzzDecodeHex(f *testing.F) {
	f.Add("00148040")
	f.Add("0x00107060")
	f.Add("FFFFFFFF")
	f.Add("00000000")
	f.Add("")
	f.Add("zz")
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input.
		_, _ = DecodeHex(s)
	})
}
