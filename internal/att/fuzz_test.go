// SPDX-License-Identifier: AGPL-3.0-or-later

package att

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{"", "0a0300", "100100ffff0028", "121000deadbeef", "1b25001234", "010a03000a", "021700", "080100ffff" + "fb349b5f80000080001000000d180000", "zz"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
