// SPDX-License-Identifier: AGPL-3.0-or-later

package oam

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"a0018446deadbeef1fff20064943432d4d45472d3030303100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"400300040000000000",
		"00280004",
		"0003000400000000020 3AABBCC",
		"0001", "00018446", "", "zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
