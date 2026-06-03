// SPDX-License-Identifier: AGPL-3.0-or-later

package btoob

import "testing"

func FuzzDecodeHex(f *testing.F) {
	f.Add("br_edr", "130006050403020105094864737404 0d040424")
	f.Add("le", "081b06050403020101021c0203094c45")
	f.Add("br_edr", "0800060504030201")
	f.Add("le", "")
	f.Add("br_edr", "zz")
	f.Fuzz(func(_ *testing.T, variant, s string) {
		// Must never panic for any input.
		_, _ = DecodeHex(variant, s)
	})
}
