// SPDX-License-Identifier: AGPL-3.0-or-later

package gxrp

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"00010104020064040200c802000000", // GVRP
		"000101080201005e0102030000",     // GMRP group
		"0001020302000000",               // GMRP service
		"0001010100",                     // bad attribute length
		"000101ff02",                     // attribute len overruns
		"0001", "000201", "", "zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
