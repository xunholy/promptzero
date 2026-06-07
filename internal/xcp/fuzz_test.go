// SPDX-License-Identifier: AGPL-3.0-or-later

package xcp

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input / direction.
func FuzzDecode(f *testing.F) {
	seeds := []string{"", "ff00", "f80000", "f508", "d0010203", "fe24", "fd07", "0500", "zz"}
	for _, s := range seeds {
		f.Add(s, "command")
		f.Add(s, "response")
		f.Add(s, "")
	}
	f.Fuzz(func(_ *testing.T, s, dir string) {
		_, _ = Decode(s, dir)
	})
}
