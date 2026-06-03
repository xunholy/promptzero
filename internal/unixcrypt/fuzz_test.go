// SPDX-License-Identifier: AGPL-3.0-or-later

package unixcrypt

import (
	"strings"
	"testing"
)

// FuzzVerify asserts the crypt(3) verifier never panics while parsing an
// arbitrary hash string (the $-delimited scheme / rounds / salt / digest
// fields). The $5$/$6$ SHA-crypt path is skipped because its cost is driven by
// the hash's rounds= field — a mutated huge-rounds input would make the fuzzer
// hang, not crash; the md5crypt ($1$/$apr1$) path and all malformed inputs
// exercise the same parsing/splitting logic cheaply.
func FuzzVerify(f *testing.F) {
	seeds := []struct{ pw, hash string }{
		{"password", "$1$abcdefgh$G//4keteveJp0qb8z2DxG/"},
		{"password", "$apr1$abcdefgh$FBwExRW4dCc8aL.OvjpIE1"},
		{"x", "$1$"},
		{"x", "$1$$"},
		{"x", "$apr1$nosalt"},
		{"", ""},
		{"x", "plaintext"},
		{"x", "$2y$10$notbcrypt"},
	}
	for _, s := range seeds {
		f.Add(s.pw, s.hash)
	}
	f.Fuzz(func(t *testing.T, pw, hash string) {
		if strings.HasPrefix(hash, "$5$") || strings.HasPrefix(hash, "$6$") {
			return // skip the rounds-driven SHA-crypt cost (hang hazard, not a crash)
		}
		_, _ = Verify(pw, hash) // must not panic
	})
}
