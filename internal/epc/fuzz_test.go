// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

import "testing"

func FuzzDecodeHex(f *testing.F) {
	f.Add("3074257BF7194E4000001A85")
	f.Add("3134257BF4499602D2000000")
	f.Add("350000A2600019003ADE56FA")
	f.Add("3414257BF400000000003039")
	f.Add("3214257BF460720000000190")
	f.Add("3314257BF40C0E400000162E")
	f.Add("310000000000000000000000")
	f.Add("320000000000000000000000")
	f.Add("FF0000000000000000000000")
	f.Add("3074")
	f.Add("")
	f.Add("zz")
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input.
		_, _ = DecodeHex(s)
	})
}
