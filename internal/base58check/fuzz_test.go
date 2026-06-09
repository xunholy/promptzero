// SPDX-License-Identifier: AGPL-3.0-or-later

package base58check_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/base58check"
)

// FuzzDecode confirms Decode never panics on arbitrary input — the Base58
// parse, the big-int conversion, the checksum, and the type identification must
// always return cleanly with a result or an error.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"",
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		"5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
		"1111111111",
		"z",
		"0OIl", // all non-Base58
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = base58check.Decode(s)
	})
}
