// SPDX-License-Identifier: AGPL-3.0-or-later

package phpass

import "testing"

// FuzzVerify asserts the phpass parser never panics on arbitrary input. The
// round exponent is capped in crypt(), so a mutated cost can't hang the fuzzer.
func FuzzVerify(f *testing.F) {
	for _, s := range []string{
		refHash, "", "$P$", "$H$Babcdefgh" + "AAAAAAAAAAAAAAAAAAAAAA",
		"$P$!abcdefghAAAA", "$X$9abcdefghAAAAAAAAAAAAAAAAAAAAAA", "$P$9",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, hash string) {
		_, _ = Verify(hash, "password") // must not panic
	})
}
