// SPDX-License-Identifier: AGPL-3.0-or-later

package hicp

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"Protocol version = 1.00;FB type = Anybus;MAC = 00:30:11:0a:0b:0c;IP = 192.168.1.50;PSWD = OFF;HN = gw01;\x00",
		"MODULE SCAN\x00",
		"Configure: 00-30-11-0a-0b-0c;IP = 10.0.0.99;HN = pwned;\x00",
		"Reconfigured\x00", "Invalid Password\x00", "To: 00-30-11-0a-0b-0c",
		"4d4f44554c45205343414e00", "= = = ;;;", "junk", "", "zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
