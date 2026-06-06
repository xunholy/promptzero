// SPDX-License-Identifier: AGPL-3.0-or-later

package etherip

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"300000112233445566778899aabb08004500001c00010000401166ce0a0000010a00000204d200350008e6d4",
		"3000ffffffffffff0011223344550806" + "0001080006040001",
		"3000" + "00112233445566778899aabb86dd" + "60000000000011401234",
		"30", "3000", "3000aabbcc", "4000aabb", "", "zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
