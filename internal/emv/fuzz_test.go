package emv

import "testing"

func FuzzParseBytes(f *testing.F) {
	for _, s := range [][]byte{{}, {0x6F}, {0x6F, 0x1A}, {0x9F, 0x10}, {0x5F, 0x2D, 0x02}, {0xFF}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseBytes(b) })
}

// FuzzDecodeTrack2 exercises the Track-2 nibble walker on arbitrary bytes —
// it must never panic on a malformed PAN / separator / length.
func FuzzDecodeTrack2(f *testing.F) {
	for _, s := range []string{
		"", "D", "4111111111111111D25122010000000F", "FFFF", "0000000000000000",
		"4111111111111111", "D25122010000000F", "9", "1234D",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeTrack2Hex(s) })
}

// FuzzDecodeDOL exercises the (tag,length) DOL walker — multi-byte tags and
// long-form lengths must not run off the buffer.
func FuzzDecodeDOL(f *testing.F) {
	for _, s := range []string{
		"", "9F3804", "9F02069F0306", "9F", "9F82", "8C", "5F", "9F660481809F",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeDOLHex(s) })
}

// FuzzDecodeAFL exercises the 4-byte AFL entry walker.
func FuzzDecodeAFL(f *testing.F) {
	for _, s := range []string{
		"", "08010100", "08010100100104", "F8010100", "00010100", "08040100",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeAFLHex(s) })
}
