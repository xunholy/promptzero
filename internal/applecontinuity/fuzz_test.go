package applecontinuity

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"00FF4C00", "0CFF4C00100506", "4C0010021B00", "", "FF"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = Decode(s) })
}

// TestRegression_ADLengthPanic covers the fuzz-found slice panic in the
// <len> FF 4C 00 prefix stripper (declared length < 3).
func TestRegression_ADLengthPanic(t *testing.T) {
	for _, s := range []string{"00FF4C00", "01FF4C00", "02FF4C0010"} {
		_, _ = Decode(s) // must not panic
	}
}
