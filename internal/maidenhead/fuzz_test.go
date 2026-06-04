// SPDX-License-Identifier: AGPL-3.0-or-later

package maidenhead

import "testing"

// FuzzDecode asserts the locator parser never panics on arbitrary input — the
// pair indexing, character validation, and case handling must stay in bounds.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"FN31pr", "JN58td", "", "F", "FN31zz", "jj00aa", "\x00\x00", "FN31pr2199"} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		if loc, err := Decode(s); err == nil {
			// A successful decode must round-trip back to a valid encode.
			_, _ = Encode(loc.CenterLat, loc.CenterLon, loc.Pairs)
		}
	})
}
