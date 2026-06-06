// SPDX-License-Identifier: AGPL-3.0-or-later

package homeplugav

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"0050a000b052aabbccddeeff", "0039a000b052010203", "0034a000b052",
		"011ca0000000", "00ffff", "0250a0", "0050", "", "zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
