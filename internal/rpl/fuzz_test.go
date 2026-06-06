// SPDX-License-Identifier: AGPL-3.0-or-later

package rpl

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"9b0100001ef001009401000020010db8000000000000000000000001", // DIO
		"9b0000000000", // DIS
		"9b0200001ec0000520010db8000000000000000000000002", // DAO
		"9b0300001e80050020010db8000000000000000000000002", // DAO-ACK
		"9b07", "9bff", "85000000", "9b01", "0x9b:01", "", "zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
