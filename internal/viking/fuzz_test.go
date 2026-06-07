// SPDX-License-Identifier: AGPL-3.0-or-later

package viking

import "testing"

// FuzzDecode exercises the Viking block decoder on arbitrary input; it must
// never panic (a malformed / wrong-length / non-Viking block returns an error
// or a Result).
func FuzzDecode(f *testing.F) {
	f.Add("f200000001a337cf")
	f.Add("f200001234567852")
	f.Add("f200000001a337ce")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Decode(s) })
}
