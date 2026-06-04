// SPDX-License-Identifier: AGPL-3.0-or-later

package uuidinfo

import "testing"

// FuzzDecode asserts the parser never panics — hex parsing, field extraction,
// and the epoch arithmetic must hold for any input.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"a8098c1a-f86e-11da-bd1a-00112444be1e", "017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
		"00000000-0000-0000-0000-000000000000", "", "xyz", "{}", "urn:uuid:",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s) // must not panic
	})
}
