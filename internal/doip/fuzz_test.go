// SPDX-License-Identifier: AGPL-3.0-or-later

package doip

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		"02fd0004000000215756575a5a5a314a5a58573030303030310e80010203040506aabbccddeeff1000",
		"02fd0005000000070e000000000000",
		"02fd0006000000090e000e800400000000",
		"02fd8001000000060e000e801003",
		"02fd00000000000101",
		"02fd8003000000050e000e8002",
		"zz",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
