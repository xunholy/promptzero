// SPDX-License-Identifier: AGPL-3.0-or-later

package hci

import "testing"

// FuzzDecode asserts Decode never panics on arbitrary input.
func FuzzDecode(f *testing.F) {
	seeds := []string{"", "01030c00", "010c20020100", "040e0401030c00", "043e0c020100112233445566778899", "02402005001122334455", "01ffff00", "0101", "zz"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
