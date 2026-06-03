// SPDX-License-Identifier: AGPL-3.0-or-later

package webpass

import "testing"

// FuzzVerify asserts the Django/Werkzeug hash parser never panics on arbitrary
// input (it parses an untrusted DB-dump hash string).
func FuzzVerify(f *testing.F) {
	for _, s := range []string{
		djangoHash, werkzeugHash, "", "pbkdf2_sha256$", "pbkdf2:sha256:",
		"pbkdf2_sha256$1$s$!!!", "pbkdf2:sha256:x$s$zz", "plaintext", "pbkdf2_sha256$1$$",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, hash string) {
		_, _ = Verify(hash, "password") // must not panic
	})
}
