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
		"$GPGSV,2,1,08,01,40,083,46,02,17,308,41,12,07,344,39,14,22,228,45*75",
		"$GPGST,172814.0,0.006,0.023,0.020,273.6,0.023,0.020,0.031*6A",
		"$GPZDA,160012.71,11,03,2004,-1,00*7D",
		"$GPGSV,2,1,08*75", "$GP", "$", "*", ",,,", "", "$GPGLL,1,N",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s) // must not panic
	})
}
