// SPDX-License-Identifier: AGPL-3.0-or-later

package pgpassword

import "testing"

// FuzzVerify asserts Verify never panics while parsing an arbitrary stored
// value (the "md5" strip, length check, hex decode). Cheap — no rounds.
func FuzzVerify(f *testing.F) {
	for _, s := range []string{fooSecret, pgX, "md5", "", "noprefix", "md5zz"} {
		f.Add("secret", "foo", s)
	}
	f.Fuzz(func(_ *testing.T, password, username, stored string) {
		_, _ = Verify(password, username, stored) // must not panic
	})
}
