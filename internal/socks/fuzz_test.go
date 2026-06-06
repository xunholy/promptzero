// SPDX-License-Identifier: AGPL-3.0-or-later

package socks

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"050100010102030401bb", "0501000420010db80000000000000000000000011f90",
		"050000010a0000010438", "05010003" + "0b" + "6578616d706c652e636f6d" + "0050",
		"05020001", "0500", "0401001709080706726f6f7400", "005a001709080706",
		"0401005000000001" + "00" + "686f73742e6578616d706c6500",
		"ff00", "04", "05", "", "zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
