// SPDX-License-Identifier: AGPL-3.0-or-later

package iso15693

import "testing"

// FuzzDecodeUID asserts the UID parser never panics on arbitrary input.
func FuzzDecodeUID(f *testing.F) {
	for _, s := range []string{
		"E004010050B2A123", "E0:02:00:00:12:34:56:78", "", "E004", "nothex", "00",
		"E0FF00000000ABCD", "e0040150abcdef01",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = DecodeUID(s) // must not panic
	})
}
