// SPDX-License-Identifier: AGPL-3.0-or-later

package ble

import "testing"

// FuzzClassifyAddress exercises the BLE address classifier across both the
// address string and the declared-type argument — neither must panic.
func FuzzClassifyAddress(f *testing.F) {
	seeds := []struct{ a, t string }{
		{"", ""}, {"C0:AA:BB:CC:DD:EE", "random"}, {"00:1A:2B:3C:4D:5E", "public"},
		{"40:AA:BB:CC:DD:EE", ""}, {"zz", "random"}, {"C0AABBCCDDEE", "bogus"},
	}
	for _, s := range seeds {
		f.Add(s.a, s.t)
	}
	f.Fuzz(func(t *testing.T, a, typ string) { _, _ = ClassifyAddress(a, typ) })
}
