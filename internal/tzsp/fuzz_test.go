// SPDX-License-Identifier: AGPL-3.0-or-later

package tzsp

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"010000120a01d60b01280c016c1201061101010166778899aabb0011223344550800",
		"0104000101", // keepalive
		"010000120a02ffd601",
		"010000120affAABB", // tag claims 0xff bytes
		"01000012",         // header only, no end tag
		"0100", "", "zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
