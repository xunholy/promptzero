// SPDX-License-Identifier: AGPL-3.0-or-later

package roce

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		"0c00ffff0000012380000456",
		"64a080018000abcd0000ff00",
		"8100ffff0000001000000000",
		"0c00ffff0000012380000456deadbeef",
		"1f00ffff0000012380000456",
		"zz",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
