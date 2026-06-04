// SPDX-License-Identifier: AGPL-3.0-or-later

package krbroast

import "testing"

// FuzzRoastLine asserts the builder never panics on arbitrary input (the
// kerberos ASN.1 decode + enc-part length split).
func FuzzRoastLine(f *testing.F) {
	for _, s := range []string{asrepHex, tgsrepHex, "6a03020100", "6b03020100", "", "zz"} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, h string) {
		_, _ = RoastLine(h) // must not panic
	})
}
