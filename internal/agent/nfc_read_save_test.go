package agent

import "testing"

// TestDumpSavedPathRE pins the firmware-message shape that
// nfcReadSaveViaDump relies on. Captured from a real Momentum
// (mntm-dev, 09-03-2026 build) running `dump` with no -p:
//
//	Dumping as "Mifare Classic"
//	Dump saved to '/ext/nfc/dump-20260424-080950.nfc'
//
//	[nfc]
//
// If a firmware update reshapes this banner, the regex breaks here
// rather than silently rendering nfc_read_save useless on Momentum.
func TestDumpSavedPathRE(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "momentum_classic",
			in:   "Dumping as \"Mifare Classic\"\nDump saved to '/ext/nfc/dump-20260424-080950.nfc'\n\n[nfc]",
			want: "/ext/nfc/dump-20260424-080950.nfc",
		},
		{
			name: "with_subdirectory",
			in:   "Dump saved to '/ext/nfc/work/badge.nfc'",
			want: "/ext/nfc/work/badge.nfc",
		},
		{
			name: "no_match",
			in:   "Authentication failed",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := dumpSavedPathRE.FindStringSubmatch(tc.in)
			got := ""
			if len(m) == 2 {
				got = m[1]
			}
			if got != tc.want {
				t.Errorf("dumpSavedPathRE on %q: got %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
