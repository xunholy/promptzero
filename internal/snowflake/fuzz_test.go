// SPDX-License-Identifier: AGPL-3.0-or-later

package snowflake

import "testing"

// FuzzDecode asserts the parser never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"175928847299117063", "0", "", "xyz", "18446744073709551615"} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s, "")
		_, _ = Decode(s, "discord")
	})
}
