package ibutton

import (
	"strings"
	"testing"
)

// TestDecode_DS1990A_RoundTrip pins a Dallas DS1990A iButton ROM ID
// with a CRC computed by this implementation. ROM bytes 01 02 03 04
// 05 06 07 compute CRC 0x0F per Dallas polynomial 0x31 (reflected).
func TestDecode_DS1990A_RoundTrip(t *testing.T) {
	got, err := Decode("01 02 03 04 05 06 07 0F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FamilyCode != 0x01 {
		t.Errorf("FamilyCode = 0x%02X; want 0x01", got.FamilyCode)
	}
	if got.FamilyHex != "0x01" {
		t.Errorf("FamilyHex = %q; want '0x01'", got.FamilyHex)
	}
	if !strings.Contains(got.FamilyName, "DS1990A") {
		t.Errorf("FamilyName = %q; want a DS1990A label", got.FamilyName)
	}
	if got.SerialHex != "020304050607" {
		t.Errorf("SerialHex = %q; want '020304050607'", got.SerialHex)
	}
	if got.CRC != 0x0F {
		t.Errorf("CRC = 0x%02X; want 0x0F", got.CRC)
	}
	if got.CRCExpected != 0x0F {
		t.Errorf("CRCExpected = 0x%02X; want 0x0F", got.CRCExpected)
	}
	if !got.CRCValid {
		t.Error("CRCValid = false; want true")
	}
	if got.ROMHex != "01020304050607"+"0F" {
		t.Errorf("ROMHex = %q", got.ROMHex)
	}
}

// TestDecode_DS18B20 pins a DS18B20 temperature-sensor ROM ID.
// Family 0x28 + serial AA BB CC DD EE FF → CRC = 0x0C.
func TestDecode_DS18B20(t *testing.T) {
	got, err := Decode("28:AA:BB:CC:DD:EE:FF:0C")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FamilyCode != 0x28 {
		t.Errorf("FamilyCode = 0x%02X; want 0x28", got.FamilyCode)
	}
	if !strings.Contains(got.FamilyName, "DS18B20") {
		t.Errorf("FamilyName = %q; want a DS18B20 label", got.FamilyName)
	}
	if !got.CRCValid {
		t.Errorf("CRCValid = false; expected = 0x%02X, got = 0x%02X",
			got.CRCExpected, got.CRC)
	}
}

// TestDecode_CRCInvalid surfaces CRCValid=false when the trailing
// byte doesn't match the computed CRC.
func TestDecode_CRCInvalid(t *testing.T) {
	// Same as DS1990A vector but with a bogus CRC byte
	got, err := Decode("01 02 03 04 05 06 07 AB")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.CRCValid {
		t.Error("CRCValid = true; want false for bogus CRC byte")
	}
	if got.CRC != 0xAB {
		t.Errorf("CRC = 0x%02X; want 0xAB (captured)", got.CRC)
	}
	if got.CRCExpected != 0x0F {
		t.Errorf("CRCExpected = 0x%02X; want 0x0F (computed)", got.CRCExpected)
	}
}

// TestDecode_AllZeroSerial pins the edge case where a real ROM ID
// has family 0x01 + all-zero serial. CRC over 01 00 00 00 00 00 00
// = 0x3D per our implementation.
func TestDecode_AllZeroSerial(t *testing.T) {
	got, err := Decode("01 00 00 00 00 00 00 3D")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.CRCValid {
		t.Errorf("CRCValid = false; expected = 0x%02X", got.CRCExpected)
	}
	if got.SerialHex != "000000000000" {
		t.Errorf("SerialHex = %q", got.SerialHex)
	}
}

// TestDecode_UnknownFamily verifies that unmapped family codes
// still produce a structured result with the raw byte surfaced.
func TestDecode_UnknownFamily(t *testing.T) {
	// 0xEE is not a documented Maxim family code as of AN1796
	got, err := Decode("EE 11 22 33 44 55 66 77")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FamilyCode != 0xEE {
		t.Errorf("FamilyCode = 0x%02X", got.FamilyCode)
	}
	if !strings.Contains(got.FamilyName, "Unknown") {
		t.Errorf("FamilyName = %q; want 'Unknown' marker", got.FamilyName)
	}
}

// TestDecode_HexPrefix tolerates a leading '0x'.
func TestDecode_HexPrefix(t *testing.T) {
	got, err := Decode("0x010203040506070F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FamilyCode != 0x01 {
		t.Errorf("FamilyCode = 0x%02X", got.FamilyCode)
	}
}

// TestDecode_Separators tolerates :, -, _, and whitespace mixed.
func TestDecode_Separators(t *testing.T) {
	got, err := Decode("01-02_03 04:05\t06 07 0F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.CRCValid {
		t.Error("CRCValid = false; want true")
	}
}

// TestDecode_TooShort rejects fewer than 8 bytes.
func TestDecode_TooShort(t *testing.T) {
	if _, err := Decode("01 02 03"); err == nil {
		t.Error("3-byte input: want error")
	}
}

// TestDecode_TooLong rejects more than 8 bytes — Cyfral / Metakom
// will have different widths.
func TestDecode_TooLong(t *testing.T) {
	if _, err := Decode("01 02 03 04 05 06 07 08 09"); err == nil {
		t.Error("9-byte input: want error")
	}
}

// TestDecode_BadHex rejects garbage input.
func TestDecode_BadHex(t *testing.T) {
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
}

// TestComputeCRC pins the polynomial implementation against the
// vectors used in the round-trip tests.
func TestComputeCRC(t *testing.T) {
	cases := []struct {
		in   []byte
		want byte
	}{
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, 0x0F},
		{[]byte{0x28, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, 0x0C},
		{[]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0x3D},
	}
	for _, c := range cases {
		if got := computeCRC(c.in); got != c.want {
			t.Errorf("computeCRC(% X) = 0x%02X; want 0x%02X", c.in, got, c.want)
		}
	}
}

// TestFamilyNameSpotChecks exercises a handful of well-known
// family codes from the lookup table.
func TestFamilyNameSpotChecks(t *testing.T) {
	cases := map[byte]string{
		0x01: "DS1990A",
		0x10: "DS1820",
		0x14: "DS1971",
		0x23: "DS1973",
		0x28: "DS18B20",
		0x29: "DS2408",
		0x2D: "DS1972",
		0x3A: "DS2413",
	}
	for code, wantSubstr := range cases {
		got := familyName(code)
		if !strings.Contains(got, wantSubstr) {
			t.Errorf("familyName(0x%02X) = %q; want substring %q", code, got, wantSubstr)
		}
	}
}

// TestDecodeBytes_BypassHex exercises the byte-input entry point
// used when the caller already holds raw bytes.
func TestDecodeBytes_BypassHex(t *testing.T) {
	got, err := DecodeBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0F})
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if !got.CRCValid {
		t.Error("CRCValid = false")
	}
}

// TestDecodeBytes_LengthCheck rejects non-8-byte input.
func TestDecodeBytes_LengthCheck(t *testing.T) {
	if _, err := DecodeBytes([]byte{0x01}); err == nil {
		t.Error("1-byte input: want error")
	}
}
