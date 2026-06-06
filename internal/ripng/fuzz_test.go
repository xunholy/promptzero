// SPDX-License-Identifier: AGPL-3.0-or-later

package ripng

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"02010000fe800000000000000000000000000001000000ff20010db8000100000000000000000000000a300220010db800020000000000000000000000004010",
		"010100000000000000000000000000000000000000000010", // whole-table request
		"0201000000112233445566778899",                     // trailing partial RTE
		"0201", "030100000", "", "zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
