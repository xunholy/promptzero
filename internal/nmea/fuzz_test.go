// SPDX-License-Identifier: AGPL-3.0-or-later

package nmea

import "testing"

// FuzzDecode asserts the parser never panics on arbitrary input — checksum
// splitting, field indexing, and the ddmm.mmmm coordinate slicing over
// untrusted pasted text must stay in bounds.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47",
		"$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A",
		"$GPGSV,2,1,08*75", "$GP", "$", "*", ",,,", "", "$GPGLL,1,N",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s) // must not panic
	})
}
