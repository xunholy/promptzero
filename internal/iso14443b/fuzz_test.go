// SPDX-License-Identifier: AGPL-3.0-or-later

package iso14443b

import "testing"

func FuzzDecodeATQB(f *testing.F) {
	f.Add("50 11223344 55667788 00 71 85")
	f.Add("50112233445566778800718512AB")
	f.Add("00112233445566778899AABB")
	f.Add("5011")
	f.Add("zzzz")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic, regardless of input.
		_, _ = DecodeATQB(s)
	})
}
