// SPDX-License-Identifier: AGPL-3.0-or-later

package presco

import "testing"

// FuzzDecode exercises the Presco block decoder on arbitrary input; it must
// never panic (a malformed / wrong-length / non-Presco block returns an error
// or a Result).
func FuzzDecode(f *testing.F) {
	f.Add("10d00000000000000000000007aabbcc")
	f.Add("10d00000000000000000000012345678")
	f.Add("10d00001000000000000000007aabbcc")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
