// SPDX-License-Identifier: AGPL-3.0-or-later

package igmpv3

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"2200d5f60000000104000002ef0101010a0000010a000002", // report
		"1114da5cef0505050a7d00020a0101010a010102",         // query
		"1114eeeb0000000000000000",                         // general query
		"220000000000ffff04000064ef010101",                 // claims many records
		"1114000000000000ff",                               // query, truncated src
		"2200", "1100", "", "zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
