// SPDX-License-Identifier: AGPL-3.0-or-later

package spiflash

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{"", "9fef4018", "03001000", "200abcde", "06", "02000000deadbeef", "77", "9f", "zz"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
