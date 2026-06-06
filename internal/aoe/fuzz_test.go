// SPDX-License-Identifier: AGPL-3.0-or-later

package aoe

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"100000010200deadbeef400008205634120000000000",
		"100000050301000000010010010202400011434f524149442045746865724472697665",
		"1c060005030100000001",
		"100000010300cafebabe000010340000000000000000",
		"1000000203" + "00" + "00000001", // MAC Mask List, raw body
		"1000000102", "10", "", "zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
