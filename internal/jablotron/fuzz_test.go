// SPDX-License-Identifier: AGPL-3.0-or-later

package jablotron

import "testing"

// FuzzDecode exercises the Jablotron block decoder on arbitrary input; it must
// never panic (a malformed / wrong-length / non-Jablotron block returns an
// error or a Result).
func FuzzDecode(f *testing.F) {
	f.Add("ffff12345678909e")
	f.Add("ffff0001b669011b")
	f.Add("ffff12345678909f")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
