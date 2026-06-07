// SPDX-License-Identifier: AGPL-3.0-or-later

package l2cap

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{"", "030004000a0300", "04000400" + "1b0500ff", "0700060001030005100101", "020040001122", "010004007f", "0300", "zz"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
