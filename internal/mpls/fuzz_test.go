// SPDX-License-Identifier: AGPL-3.0-or-later

package mpls

import "testing"

func FuzzDecode(f *testing.F) {
	seeds := []string{
		labelBOS + innerIPv4UDP,   // inner IPv4 -> ipdecode path
		labelBOS + innerIPv6UDP,   // inner IPv6 -> ipdecode path
		"00000140" + innerIPv4UDP, // IPv4 Explicit NULL bottom label
		labelBOS + "45AB",         // IP-typed garbage
		labelBOS + "00000000AABB", // EoMPLS (non-IP)
		"00064140",                // label only, no payload
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input, including malformed payloads
		// routed into the IP decoder.
		_, _ = Decode(s)
	})
}
