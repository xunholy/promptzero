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

// The fixed-width / TLV status-word decoders below all ingest raw EMV tag
// bytes from an attacker-controllable card, so they must never panic on a
// malformed length or value — only return an error. Each fuzzes the hex
// wrapper, which exercises the hex parse and the byte decoder together.

// FuzzDecodeCVMResults — tag 9F34, 3 bytes (CVM Results).
func FuzzDecodeCVMResults(f *testing.F) {
	for _, s := range []string{"", "1E0300", "420000", "FF", "010203", "1E03"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeCVMResultsHex(s) })
}

// FuzzDecodeCVMList — tag 8E, two 4-byte amounts followed by 2-byte CV rules.
func FuzzDecodeCVMList(f *testing.F) {
	for _, s := range []string{"", "00000000000000004203", "FFFFFFFF", "00", "0000000000000000"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeCVMListHex(s) })
}

// FuzzDecodeAIP — tag 82, 2 bytes (Application Interchange Profile).
func FuzzDecodeAIP(f *testing.F) {
	for _, s := range []string{"", "5800", "FF", "0000", "FFFF"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeAIPHex(s) })
}

// FuzzDecodeTSI — tag 9B, 2 bytes (Transaction Status Information).
func FuzzDecodeTSI(f *testing.F) {
	for _, s := range []string{"", "E800", "FF", "0000"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeTSIHex(s) })
}

// FuzzDecodeTVR — tag 95, 5 bytes (Terminal Verification Results).
func FuzzDecodeTVR(f *testing.F) {
	for _, s := range []string{"", "0000008000", "FFFFFFFFFF", "00", "0000000000"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeTVRHex(s) })
}
