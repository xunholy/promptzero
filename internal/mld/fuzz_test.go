// SPDX-License-Identifier: AGPL-3.0-or-later

package mld

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		"820000002710000000000000000000000000000000000000",
		"8300000000000000ff020000000000000000000000010003",
		"8200000027100000ff0200000000000000000000000000fb027d000120010db8000000000000000000000001",
		"8f0000000000000102000000ff0200000000000000000000000000fb",
		"80000000",
		"zz",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
