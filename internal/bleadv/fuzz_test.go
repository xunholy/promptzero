// SPDX-License-Identifier: AGPL-3.0-or-later

package bleadv

import "testing"

// FuzzDecode exercises the AD-structure walker on arbitrary input; it must
// never panic (a malformed / truncated payload returns an error or a Result).
func FuzzDecode(f *testing.F) {
	f.Add("0201061aff4c000215e2c56db5dffb48d2b060d0f5a71096e000000000c5")
	f.Add("0201060303aafe0e16aafe10eb016578616d706c6507")
	f.Add("020106020aeb0309486903194000")
	f.Add("ff16aabb")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
