// SPDX-License-Identifier: AGPL-3.0-or-later

package dcc2

import "testing"

// FuzzVerify asserts Verify never panics while parsing an arbitrary $DCC2$
// string (prefix strip, '#' split, iteration/hex validation). PBKDF2 only runs
// once the hash is well-formed (and the iteration count is capped), so inputs
// stay cheap.
func FuzzVerify(f *testing.F) {
	for _, s := range []string{
		"$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f",
		"$DCC2$", "$DCC2$10240#tom", "$DCC2$x#y#z", "", "notadcc2",
	} {
		f.Add("hashcat", s)
	}
	f.Fuzz(func(_ *testing.T, password, hash string) {
		_, _ = Verify(password, hash) // must not panic
	})
}
