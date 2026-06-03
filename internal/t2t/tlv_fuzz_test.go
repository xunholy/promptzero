// SPDX-License-Identifier: AGPL-3.0-or-later

package t2t

import "testing"

func FuzzDecodeTLV(f *testing.F) {
	f.Add("0103AABBCC0309D101055402656E6869FE")
	f.Add("0000FE")
	f.Add("FDFF0002AABB")
	f.Add("030AD1")
	f.Add("7A021234FE")
	f.Add("")
	f.Add("zz")
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input.
		_, _ = DecodeTLVHex(s)
	})
}
