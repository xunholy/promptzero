// SPDX-License-Identifier: AGPL-3.0-or-later

package pppoe

import "testing"

func FuzzDecode(f *testing.F) {
	seeds := []string{
		session("0021", innerIPv4UDP), // inner IPv4 -> ipdecode path
		session("0057", innerIPv6UDP), // inner IPv6 -> ipdecode path
		session("0021", "45AB"),       // IP-typed garbage
		session("C021", "01010004"),   // LCP (control)
		"11000001001E",                // header only
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		// Must never panic for any input, including malformed PPP payloads
		// routed into the IP decoder.
		_, _ = Decode(s)
	})
}
