// SPDX-License-Identifier: AGPL-3.0-or-later

package noralsy

import "testing"

// FuzzDecode exercises the Noralsy block decoder on arbitrary input; it must
// never panic (a malformed / wrong-length / non-Noralsy block returns an error
// or a Result).
func FuzzDecode(f *testing.F) {
	f.Add("bb0214ff1232104567370000")
	f.Add("bb0214ff0009900001170000")
	f.Add("bb0214ffabc210def0270000")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
