// SPDX-License-Identifier: AGPL-3.0-or-later

package vin

import "testing"

// FuzzDecode exercises the VIN decoder on arbitrary strings — the length /
// character-set checks and the fixed-offset field slicing must never panic.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"", "1M8GDM9AXKP042788", "11111111111111111", "1M8GDM9AXKP04278I",
		"AAAAAAAAAAAAAAAAA", "12345678901234567", "1M8GDM9AXKP0427",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = Decode(s) })
}
