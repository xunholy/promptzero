// SPDX-License-Identifier: AGPL-3.0-or-later

package macaddr

import "testing"

// FuzzClassify exercises the MAC classifier — separator stripping, the length
// check, and hex parsing must never panic.
func FuzzClassify(f *testing.F) {
	for _, s := range []string{"", "00:1A:2B:3C:4D:5E", "DE:AD:BE:EF:00:01", "FFFFFFFFFFFF", "zz", "001a2b3c4d5e"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = Classify(s) })
}

// FuzzRecoverMAC exercises the IPv6 -> MAC recovery — IP parsing and the
// low-64-bit slice must never panic.
func FuzzRecoverMAC(f *testing.F) {
	for _, s := range []string{"", "fe80::21a:2bff:fe3c:4d5e", "2001:db8::1", "::1", "192.168.1.1", "not-an-ip", "::"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = RecoverMAC(s) })
}
