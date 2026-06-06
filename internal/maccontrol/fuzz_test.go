// SPDX-License-Identifier: AGPL-3.0-or-later

package maccontrol

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"0001ffff0000000000000000",                       // PAUSE
		"010100850064000000c80000000000000000012c000000", // PFC
		"00030102030401020000",                           // REPORT
		"0002010203040000",                               // GATE
		"0004010203040001010002030000",                   // REGISTER_REQ
		"0005010203040100020003",                         // REGISTER
		"0999aabbccdd", "0001", "00", "", "zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
