package tools

import "testing"

// FuzzDecodeEM4100 exercises the EM4100 customer-ID decoder on arbitrary
// strings — it parses a raw tag value read off an attacker-controllable
// RFID badge, so a malformed length or non-hex input must return an
// error, never panic. (The 64-bit wire frame is covered separately by
// FuzzDecodeEM4100Frame.)
func FuzzDecodeEM4100(f *testing.F) {
	for _, s := range []string{"", "0000000000", "DEADBEEF12", "FFFFFFFFFF", "XYZ", "12345", "12 34 56 78 90"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeEM4100(s) })
}

// FuzzDecodeWiegand exercises the Wiegand format dispatcher and its
// per-length (26/34/35/37-bit) parity walkers on arbitrary bit counts and
// patterns — the bits come from a raw badge capture, so any length or
// content must return an error rather than index out of range. The fuzz
// []byte is mapped one bool per byte (low bit) so the fuzzer can reach the
// supported lengths by varying input size.
func FuzzDecodeWiegand(f *testing.F) {
	for _, n := range []int{0, 1, 26, 34, 35, 37, 64} {
		f.Add(make([]byte, n))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		bits := make([]bool, len(b))
		for i, v := range b {
			bits[i] = v&1 == 1
		}
		_, _ = DecodeWiegand(bits)
	})
}
