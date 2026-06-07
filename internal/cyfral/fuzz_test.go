// SPDX-License-Identifier: AGPL-3.0-or-later

package cyfral

import "testing"

// FuzzDecode exercises the Cyfral frame decoder on arbitrary input; it must
// never panic (a malformed / wrong-length / non-Cyfral frame returns an error
// or a Result).
func FuzzDecode(f *testing.F) {
	f.Add("1edb7edb71")
	f.Add("1777777771")
	f.Add("1eeeeeeee1")
	f.Add("2edb7edb71")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
