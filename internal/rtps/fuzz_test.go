// SPDX-License-Identifier: AGPL-3.0-or-later

package rtps

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"525450530204010301020304050607080 90a0b0c09010800112233445566778815011000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"52545053020401010000000000000000000000000e0c0c00aabbccddeeff00112233445566",
		"52545053020401100000000000000000000000000700000401020304",
		"52545053", "4e4f5045", "52545053ffffffffffffffffffffffffffffffff15ff0000", "", "zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
