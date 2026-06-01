package obd2

import "testing"

func FuzzPID(f *testing.F) {
	for _, s := range []string{"410C1AF8", "41", "4110", "010C", "030C", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeResponse(s); _, _ = DecodeDTCResponse(s) })
}
