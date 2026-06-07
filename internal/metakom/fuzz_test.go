// SPDX-License-Identifier: AGPL-3.0-or-later

package metakom

import "testing"

// FuzzDecode exercises the Metakom key decoder on arbitrary input; it must never
// panic (a malformed / wrong-length key returns an error or a Result).
func FuzzDecode(f *testing.F) {
	f.Add("030F33C3")
	f.Add("010F33C3")
	f.Add("00000000")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
