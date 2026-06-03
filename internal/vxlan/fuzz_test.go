// SPDX-License-Identifier: AGPL-3.0-or-later

package vxlan

import "testing"

func FuzzDecode(f *testing.F) {
	seeds := []string{
		vxlanFrame("0800", innerIPv4UDP), // inner IPv4 -> ipdecode path
		vxlanFrame("86DD", innerIPv6UDP), // inner IPv6 -> ipdecode path
		vxlanFrame("0800", "AABB"),       // IP-typed garbage
		vxlanFrame("0806", "0001"),       // non-IP (ARP)
		"0800000000006400",               // header only, no inner
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input, including malformed inner frames
		// routed into the IP decoder.
		_, _ = Decode(s)
	})
}
