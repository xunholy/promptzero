// SPDX-License-Identifier: AGPL-3.0-or-later

package objectid

import "testing"

// FuzzDecode asserts the parser never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"507f1f77bcf86cd799439011", "", "xyz", `ObjectId("00")`, "000000000000000000000000"} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
