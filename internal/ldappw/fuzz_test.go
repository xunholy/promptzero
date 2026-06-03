// SPDX-License-Identifier: AGPL-3.0-or-later

package ldappw

import "testing"

// FuzzVerify asserts the verifier never panics while parsing an arbitrary
// stored value (the {SCHEME}base64 split, digest/salt boundary, base64 decode).
// Unlike the SHA-crypt path there is no rounds= cost field, so every input is
// cheap to exercise.
func FuzzVerify(f *testing.F) {
	seeds := []string{
		shaSecret, md5Secret, sshaSecret, sha256Secret, ssha512Secret,
		"{SSHA}", "{SHA}YWJj", "{BOGUS}AAAA", "noscheme", "{", "}", "",
	}
	for _, s := range seeds {
		f.Add("secret", s)
	}
	f.Fuzz(func(_ *testing.T, password, stored string) {
		_, _ = Verify(password, stored) // must not panic
	})
}
