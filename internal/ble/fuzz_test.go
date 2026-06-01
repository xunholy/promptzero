package ble

import "testing"

func FuzzDecodeContinuity(f *testing.F) {
	for _, s := range []string{"00FF4C00", "0CFF4C00100506", "4C0010021B00", "", "FF"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = Decode(s) })
}

func FuzzDecodeEddystone(f *testing.F) {
	for _, s := range []string{"0016AAFE", "0B16AAFE100200036F6F", "AAFE100200", "", "16"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeEddystone(s) })
}

// TestRegression_ADLengthPanic covers the fuzz-found slice panic in the
// <len> FF 4C 00 / <len> 16 AA FE prefix strippers (declared length < 3).
func TestRegression_ADLengthPanic(t *testing.T) {
	for _, s := range []string{"00FF4C00", "01FF4C00", "02FF4C0010"} {
		if _, err := Decode(s); err != nil {
			_ = err // must not panic; an error or clean no-match is fine
		}
	}
	for _, s := range []string{"0016AAFE", "0116AAFE", "0216AAFE10"} {
		_, _ = DecodeEddystone(s) // must not panic
	}
}
