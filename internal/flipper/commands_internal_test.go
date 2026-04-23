package flipper

import "testing"

// TestMomentumDumpProtocolToken pins the canonical → Momentum-token map.
// Validated against real Momentum hardware: the verbose canonical names
// (e.g. "Mifare_Classic") are rejected by Momentum's `dump -p` parser
// with `Unable to parse value 'Mifare_Classic' for key 'p'`. The short
// tokens (mfc/mfu/mfp/felica) are what the firmware actually accepts.
// New protocol names should be added here in lockstep with the wrapper.
func TestMomentumDumpProtocolToken(t *testing.T) {
	cases := map[string]string{
		"Mifare_Classic":    "mfc",
		"mifare_classic":    "mfc",
		"Mifare Classic":    "mfc",
		"classic":           "mfc",
		"Mifare_Ultralight": "mfu",
		"NTAG215":           "mfu",
		"Mifare_Plus":       "mfp",
		"FeliCa":            "felica",
		"unknown_proto":     "unknown_proto",
	}
	for in, want := range cases {
		if got := momentumDumpProtocolToken(in); got != want {
			t.Errorf("momentumDumpProtocolToken(%q) = %q, want %q", in, got, want)
		}
	}
}
