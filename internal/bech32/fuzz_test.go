// SPDX-License-Identifier: AGPL-3.0-or-later

package bech32_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/bech32"
)

// FuzzDecode confirms Decode never panics on arbitrary input — the separator
// split, the charset map, the polymod checksum, the 5→8-bit regroup, and the
// SegWit interpretation must always return cleanly with a result or an error.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"",
		"A12UEL5L",
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		"npub1xxxxxxxx",
		"1",
		"bc1",
		"!!!!!!!!",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = bech32.Decode(s)
	})
}
