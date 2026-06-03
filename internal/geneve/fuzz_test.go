// SPDX-License-Identifier: AGPL-3.0-or-later

package geneve

import "testing"

func FuzzDecode(f *testing.F) {
	seeds := []string{
		geneveHdr("0800") + innerIPv4UDP,                                       // direct inner IPv4
		geneveHdr("86DD") + innerIPv6UDP,                                       // direct inner IPv6
		geneveHdr("6558") + "AABBCCDDEEFF112233445566" + "0800" + innerIPv4UDP, // TEB inner IPv4
		geneveHdr("0800") + "AABB",                                             // IP-typed garbage
		geneveHdr("8847") + "AABBCCDD",                                         // MPLS (non-IP)
		"0000655800006400",                                                     // header only
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input, including malformed inner payloads
		// routed into the IP decoder.
		_, _ = Decode(s)
	})
}
