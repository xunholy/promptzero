// SPDX-License-Identifier: AGPL-3.0-or-later

package usbpd

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{"", "4100", "81112c910124", "821012345678", "8111c890418b", "41", "zz"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
