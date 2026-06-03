// SPDX-License-Identifier: AGPL-3.0-or-later

package icmp

import "testing"

func FuzzDecode(f *testing.F) {
	seeds := []string{
		"0800 0000 00010001", // echo request
		"0303 0000 00000000 4500001C00000000401100000A0000010A00000204D2003500080000",     // dest-unreach + inner IPv4/UDP
		"0300 0000 00000000 60000000000811400000000000000000000000000000000104D200350008", // v6 time-exceeded + inner IPv6
		"0303 0000 00000000 AABBCC", // garbage embedded
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input, including malformed embedded
		// packets routed into the IP decoder.
		_, _ = Decode(s, "")
		_, _ = Decode(s, "v6")
	})
}
