// SPDX-License-Identifier: AGPL-3.0-or-later

package ulid

import "testing"

// FuzzDecode asserts the parser never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"01ARZ3NDEKTSV4RRFFQ69G5FAV", "", "xyz", "00000000000000000000000000", "8ZZZZZZZZZZZZZZZZZZZZZZZZZ"} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
