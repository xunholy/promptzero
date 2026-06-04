// SPDX-License-Identifier: AGPL-3.0-or-later

package httpmsg

import "testing"

// FuzzDecode asserts the text-protocol parser never panics on arbitrary
// input — field splitting, index math, and length handling over untrusted
// pasted text must stay in bounds.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"", "\n", ":", "a:b:c", "0", "\x00\x01\x02"} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s) // must not panic
	})
}
