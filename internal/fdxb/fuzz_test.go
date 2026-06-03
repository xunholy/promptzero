// SPDX-License-Identifier: AGPL-3.0-or-later

package fdxb

import "testing"

func FuzzDecodeHex(f *testing.F) {
	f.Add("AA25169A039F00003851")
	f.Add("05D94D190421 0001")
	f.Add("AA25169A039F0000 3851 ABCDEF")
	f.Add("AABBCC")
	f.Add("")
	f.Add("zz")
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input.
		_, _ = DecodeHex(s)
	})
}
