package desfire

import (
	"testing"
)

// TestDecode_EmptyAID pins the all-zero AID (card master /
// default).
func TestDecode_EmptyAID(t *testing.T) {
	got, err := Decode("000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Special != "empty" {
		t.Errorf("Special = %q; want 'empty'", got.Special)
	}
	if got.ApplicationName != "Card master / default (no application)" {
		t.Errorf("ApplicationName = %q", got.ApplicationName)
	}
}

// TestDecode_MIFAREClassicEmulation pins the 0xF40000 AID —
// the special value DESFire uses when emulating MIFARE Classic.
func TestDecode_MIFAREClassicEmulation(t *testing.T) {
	got, err := Decode("F40000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Special != "mifare_classic" {
		t.Errorf("Special = %q; want 'mifare_classic'", got.Special)
	}
	if got.ApplicationName != "MIFARE Classic emulation" {
		t.Errorf("ApplicationName = %q", got.ApplicationName)
	}
	if !got.MADFormatted {
		t.Error("F40000 should be MAD-formatted (high nibble F)")
	}
	if got.Category != "MIFARE Classic emulation" {
		t.Errorf("Category = %q", got.Category)
	}
}

// TestDecode_WildcardAID pins 0xFFFFFF.
func TestDecode_WildcardAID(t *testing.T) {
	got, err := Decode("FFFFFF")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Special != "wildcard" {
		t.Errorf("Special = %q; want 'wildcard'", got.Special)
	}
}

// TestDecode_TransitMAD pins a transit-application AID (MAD
// function code 0xF48).
func TestDecode_TransitMAD(t *testing.T) {
	// AID 0xF48484 → function code top 12 bits = 0xF48, sub
	// = 0x484
	got, err := Decode("F48484")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.MADFormatted {
		t.Error("F48484 should be MAD-formatted")
	}
	if got.FunctionCode != 0xF48 {
		t.Errorf("FunctionCode = 0x%03X; want 0xF48", got.FunctionCode)
	}
	if got.Category != "Transit applications" {
		t.Errorf("Category = %q", got.Category)
	}
	if got.VendorSubID != 0x484 {
		t.Errorf("VendorSubID = 0x%03X; want 0x484", got.VendorSubID)
	}
}

// TestDecode_BankingMAD pins the banking category (0xF44).
func TestDecode_BankingMAD(t *testing.T) {
	got, err := Decode("F44400")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Category != "Banking" {
		t.Errorf("Category = %q; want 'Banking'", got.Category)
	}
	if got.ApplicationName != "Banking (legacy MAD slot)" {
		t.Errorf("ApplicationName = %q", got.ApplicationName)
	}
}

// TestDecode_RetailMAD pins the retail/loyalty category (0xFA4).
// 0xFA4800 = Adam Opel Card.
func TestDecode_RetailMAD(t *testing.T) {
	got, err := Decode("FA4800")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Category != "Retail / loyalty" {
		t.Errorf("Category = %q", got.Category)
	}
	if got.ApplicationName != "Adam Opel Card / Opel loyalty" {
		t.Errorf("ApplicationName = %q", got.ApplicationName)
	}
}

// TestDecode_OVChipkaart pins the Dutch transit OV-chipkaart
// well-known AID 0x9011F2 (not MAD-formatted; high nibble 9).
func TestDecode_OVChipkaart(t *testing.T) {
	got, err := Decode("9011F2")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MADFormatted {
		t.Error("9011F2 should NOT be MAD-formatted (high nibble 9)")
	}
	if got.ApplicationName != "OV-chipkaart (NL)" {
		t.Errorf("ApplicationName = %q", got.ApplicationName)
	}
}

// TestDecode_HIDiCLASS pins the HID iCLASS-SE NDEF AID.
func TestDecode_HIDiCLASS(t *testing.T) {
	got, err := Decode("484952")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ApplicationName != "HID iCLASS-SE NDEF" {
		t.Errorf("ApplicationName = %q", got.ApplicationName)
	}
}

// TestDecode_UnknownAID — an AID not in our catalog still
// decodes structurally (just no ApplicationName).
func TestDecode_UnknownAID(t *testing.T) {
	got, err := Decode("123456")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Hex != "123456" {
		t.Errorf("Hex = %q", got.Hex)
	}
	if got.MADFormatted {
		t.Error("123456 should not be MAD-formatted (high nibble 1)")
	}
	if got.ApplicationName != "" {
		t.Errorf("ApplicationName = %q; want empty", got.ApplicationName)
	}
}

// TestDecode_NonMADHighNibble — high nibbles 0x0-0xE are not
// MAD-formatted.
func TestDecode_NonMADHighNibble(t *testing.T) {
	for _, in := range []string{"012345", "456789", "ABCDEF"} {
		got, err := Decode(in)
		if err != nil {
			t.Errorf("Decode(%q): %v", in, err)
			continue
		}
		if got.MADFormatted {
			t.Errorf("Decode(%q): MADFormatted = true; want false", in)
		}
	}
}

// TestDecode_HexInputVariants — '0x' prefix and separators.
func TestDecode_HexInputVariants(t *testing.T) {
	cases := []string{
		"0xF40000",
		"F4:00:00",
		"F4-00-00",
		"f4 00 00",
	}
	for _, in := range cases {
		got, err := Decode(in)
		if err != nil {
			t.Errorf("Decode(%q): %v", in, err)
			continue
		}
		if got.Special != "mifare_classic" {
			t.Errorf("Decode(%q): Special = %q", in, got.Special)
		}
	}
}

// TestDecode_BadInput — empty / wrong length / invalid hex.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Decode("ABCD"); err == nil {
		t.Error("4-char input: want error")
	}
	if _, err := Decode("ZZZZZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestMADCategoryTable spot-checks the function-code → category
// lookup.
func TestMADCategoryTable(t *testing.T) {
	cases := map[int]string{
		0xF40: "MIFARE Classic emulation",
		0xF48: "Transit applications",
		0xF44: "Banking",
		0xFA4: "Retail / loyalty",
		0xFCA: "Access control",
		0xFCC: "Parking",
		0xFE4: "Health",
		0x123: "", // Not a MAD function code
	}
	for fc, want := range cases {
		if got := madCategory(fc); got != want {
			t.Errorf("madCategory(0x%03X) = %q; want %q", fc, got, want)
		}
	}
}

// TestDecode_VendorSubIDExtraction confirms the bottom 12 bits
// are isolated correctly for MAD AIDs.
func TestDecode_VendorSubIDExtraction(t *testing.T) {
	// AID 0xF48ABC → function 0xF48, sub 0xABC
	got, err := Decode("F48ABC")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.VendorSubID != 0xABC {
		t.Errorf("VendorSubID = 0x%03X; want 0xABC", got.VendorSubID)
	}
	if got.VendorSubIDHex != "ABC" {
		t.Errorf("VendorSubIDHex = %q; want 'ABC'", got.VendorSubIDHex)
	}
}
