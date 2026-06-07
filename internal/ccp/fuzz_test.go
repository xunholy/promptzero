// SPDX-License-Identifier: AGPL-3.0-or-later

package ccp

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input / direction.
func FuzzDecode(f *testing.F) {
	seeds := []string{"", "012a0201ffffffff", "122b01", "182c", "ff002a", "ff332b", "fe19", "05aabbccdd", "zz"}
	for _, s := range seeds {
		f.Add(s, "command")
		f.Add(s, "response")
		f.Add(s, "")
	}
	f.Fuzz(func(_ *testing.T, s, dir string) {
		_, _ = Decode(s, dir)
	})
}
