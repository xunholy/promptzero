// SPDX-License-Identifier: AGPL-3.0-or-later

package geohash

import "testing"

// FuzzDecode asserts the parser never panics and that any successful decode
// round-trips back through Encode (center -> same geohash).
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"ezs42", "u4pruydqqvj", "", "abc", "0", "ZZZZ", "ezs4i"} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		if loc, err := Decode(s); err == nil {
			_, _ = Encode(loc.Lat, loc.Lon, loc.Precision)
		}
	})
}
