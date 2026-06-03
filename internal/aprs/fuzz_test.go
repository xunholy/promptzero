// SPDX-License-Identifier: AGPL-3.0-or-later

package aprs

import "testing"

// FuzzDecode asserts the decoder never panics on arbitrary input — TNC2 text,
// hex AX.25 bytes, and malformed/truncated weather reports routed through the
// '_' field walker (the untrusted paste-and-decode surface).
func FuzzDecode(f *testing.F) {
	seeds := []string{
		"N0CALL>APRS:_10090556c220s004g005t077r000p000P000h50b09900wRSW",
		"WX>APRS:_01011200c090s012g025t-05r012p034P056h00b10134",
		"RAINWX>APRS:_10090556c...s...g...t...P012Jim",
		"WX>APRS:!4903.50N/07201.75W_220/004g005t077r000p000P000h50b09900wRSW",
		"WX>APRS:@092345z4903.50N/07201.75W_220/004g005t-07r000p000P000h50b09900wRSW",
		"WX>APRS:!4903.50N/07201.75W_Just a comment",
		"S>APRS:_01010000c000s000g000t050L123",
		"S>APRS:_1009",
		"CALL>DEST:!4903.50N/07201.75W-Test",
		"CALL>DEST::ADDRESSEE:hello{1",
		"_",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s) // must not panic
	})
}
