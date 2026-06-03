// SPDX-License-Identifier: AGPL-3.0-or-later

package mysqlpw

import "testing"

// FuzzVerify asserts Verify never panics while parsing an arbitrary stored
// hash (the '*' strip, length check, hex decode). It is cheap — no rounds.
func FuzzVerify(f *testing.F) {
	for _, s := range []string{pwPassword, pw123456, "*", "", "noprefix", "*zz"} {
		f.Add("password", s)
	}
	f.Fuzz(func(_ *testing.T, password, hash string) {
		_, _ = Verify(password, hash) // must not panic
	})
}
