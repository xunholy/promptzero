// SPDX-License-Identifier: AGPL-3.0-or-later

package awskey_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/awskey"
)

// FuzzDecode confirms Decode never panics — the length check, prefix lookup,
// base32 decode, and bit extraction must always return cleanly.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"",
		"ASIAY34FZKBOKMUTVV7A",
		"AKIA",
		"ZZZZZZZZZZZZZZZZZZZZ",
		"AKIA0189000000000000",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = awskey.Decode(s)
	})
}
