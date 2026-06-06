// SPDX-License-Identifier: AGPL-3.0-or-later

package icmpext

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"",
		"2000dfff0008010103e801400014020d0000000700010000c0000201000005dc",
		"2000dfff000c010100064aff000c810a",
		"2000dfffffff0101deadbeef",
		"20001234",
		"zz",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
