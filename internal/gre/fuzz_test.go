// SPDX-License-Identifier: AGPL-3.0-or-later

package gre

import "testing"

func FuzzDecode(f *testing.F) {
	seeds := []string{
		"00000800" + innerIPv4UDP, // IPv4-typed payload -> ipdecode path
		"000086DD" + innerIPv6UDP, // IPv6-typed payload -> ipdecode path
		"00000800AABB",            // IP-typed garbage
		"00006558AABBCC",          // non-IP payload
		"30008847",                // flags + MPLS-ish
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
