package jtag

import (
	"strings"
	"testing"
)

// TestDecode_ARMCortexM_JTAG_DP pins the canonical ARM
// Cortex-M JTAG-DP IDCODE: 0x4BA00477.
//
// Bit layout:
//
//	bits 31..28 = 4   (Version)
//	bits 27..12 = 0xBA00 (Part Number = ARM JTAG-DP)
//	bits 11..1  = 0x23B (Manufacturer ID — IEEE 1149.1
//	               encoding of ARM's JEP106 entry: 4
//	               continuation bytes + byte 0x3B)
//	bit  0      = 1   (Fixed bit)
//
// Resolving: manuf = (0x4BA00477 >> 1) & 0x7FF = 0x23B → "ARM",
// part = (0x4BA00477 >> 12) & 0xFFFF = 0xBA00 → "ARM Cortex-M
// JTAG-DP", version = 4.
func TestDecode_ARMCortexM_JTAG_DP(t *testing.T) {
	got, err := Decode("4BA00477")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ManufacturerID != 0x23B {
		t.Errorf("ManufacturerID = 0x%X; want 0x23B", got.ManufacturerID)
	}
	if got.ManufacturerName != "ARM" {
		t.Errorf("ManufacturerName = %q; want 'ARM'", got.ManufacturerName)
	}
	if got.PartNumber != 0xBA00 {
		t.Errorf("PartNumber = 0x%X; want 0xBA00", got.PartNumber)
	}
	if got.PartName != "ARM Cortex-M JTAG-DP" {
		t.Errorf("PartName = %q", got.PartName)
	}
	if got.Version != 4 {
		t.Errorf("Version = %d; want 4", got.Version)
	}
	if !got.FixedBitValid {
		t.Error("FixedBitValid should be true (bit 0 = 1)")
	}
}

// TestDecode_STM32F4 pins an STM32F411xx IDCODE — a common
// hobbyist Cortex-M4 part. STMicro manufacturer code 0x020,
// part number 0x6431, version 1: 0x16431041.
//
// Verify: (0x16431041 >> 1) & 0x7FF = 0x020 ✓
//
//	(0x16431041 >> 12) & 0xFFFF = 0x6431 ✓
//	(0x16431041 >> 28) & 0xF = 0x1
//	bit 0 = 1
func TestDecode_STM32F4(t *testing.T) {
	got, err := Decode("16431041")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ManufacturerName != "SGS/Thomson" {
		t.Errorf("ManufacturerName = %q; want 'SGS/Thomson' (STMicro pre-rename)",
			got.ManufacturerName)
	}
	if got.PartName != "STM32F411xx" {
		t.Errorf("PartName = %q; want 'STM32F411xx'", got.PartName)
	}
}

// TestDecode_NordicNRF52840 pins Nordic's nRF52840 IDCODE.
// Nordic JEP106 = 0x489, part 0x1051. Build the IDCODE:
//
//	bit 0 = 1
//	bits 1..11 = 0x489 (manuf)
//	bits 12..27 = 0x1051 (part)
//	bits 28..31 = 0 (version)
//
// = (0x1051 << 12) | (0x489 << 1) | 1
// = 0x01051000 | 0x912 | 1 = 0x01051913
func TestDecode_NordicNRF52840(t *testing.T) {
	got, err := Decode("01051913")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ManufacturerName != "Nordic Semiconductor" {
		t.Errorf("ManufacturerName = %q; want Nordic", got.ManufacturerName)
	}
	if got.PartName != "nRF52840" {
		t.Errorf("PartName = %q; want 'nRF52840'", got.PartName)
	}
}

// TestDecode_UnknownVendor — manufacturer code not in the
// JEP106 table still yields a structured decode with the raw
// numeric values but no human names.
func TestDecode_UnknownVendor(t *testing.T) {
	// manuf = 0x7FF (not assigned), part = 0xDEAD, ver = 0xC.
	// = (0xC << 28) | (0xDEAD << 12) | (0x7FF << 1) | 1
	// = 0xC0000000 | 0x0DEAD000 | 0xFFF | 1
	// = 0xCDEADFFF
	got, err := Decode("CDEADFFF")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ManufacturerID != 0x7FF {
		t.Errorf("ManufacturerID = 0x%X; want 0x7FF", got.ManufacturerID)
	}
	if got.ManufacturerName != "" {
		t.Errorf("ManufacturerName = %q; want empty for unknown vendor",
			got.ManufacturerName)
	}
	if got.PartNumber != 0xDEAD {
		t.Errorf("PartNumber = 0x%X", got.PartNumber)
	}
	if got.PartName != "" {
		t.Errorf("PartName = %q; want empty", got.PartName)
	}
}

// TestDecode_FixedBitZero surfaces FixedBitValid=false when
// bit 0 is 0 (malformed IDCODE — IEEE 1149.1 mandates 1).
func TestDecode_FixedBitZero(t *testing.T) {
	// Same as ARM Cortex-M but with bit 0 = 0: 0x4BA00476.
	got, err := Decode("4BA00476")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FixedBitValid {
		t.Error("FixedBitValid should be false when bit 0 = 0")
	}
	if got.FixedBit != 0 {
		t.Errorf("FixedBit = %d; want 0", got.FixedBit)
	}
}

// TestDecode_0xPrefixAndSeparators exercises the operator-
// tolerant input path: 0x prefix + ':' / '-' separators.
func TestDecode_0xPrefixAndSeparators(t *testing.T) {
	for _, in := range []string{
		"0x4BA00477",
		"4B:A0:04:77",
		"4B-A0-04-77",
		"  4B A0 04 77  ",
	} {
		got, err := Decode(in)
		if err != nil {
			t.Errorf("Decode(%q): %v", in, err)
			continue
		}
		if got.PartName != "ARM Cortex-M JTAG-DP" {
			t.Errorf("Decode(%q): PartName = %q", in, got.PartName)
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
	if _, err := Decode("ZZZZZZZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecodeUint32_DirectlyConstructed pins the integer-input
// variant against a value we've built explicitly. ESP32 IDCODE
// = 0x120034E5 historical; but our table uses a different one.
// Use the ARM Cortex-M value directly.
func TestDecodeUint32_DirectlyConstructed(t *testing.T) {
	got := DecodeUint32(0x4BA00477)
	if got.PartName != "ARM Cortex-M JTAG-DP" {
		t.Errorf("DecodeUint32: PartName = %q", got.PartName)
	}
	if got.Hex != "4BA00477" {
		t.Errorf("DecodeUint32: Hex = %q", got.Hex)
	}
}

// TestJEP106TableSpotCheck cross-checks a handful of well-known
// IDCODE-encoded manufacturer codes against the table.
func TestJEP106TableSpotCheck(t *testing.T) {
	cases := map[uint16]string{
		0x009: "Intel",
		0x015: "Philips",
		0x017: "Texas Instruments",
		0x01F: "Atmel",
		0x020: "SGS/Thomson",
		0x029: "Microchip Technology",
		0x041: "Infineon (Siemens)",
		0x23B: "ARM",
		0x489: "Nordic Semiconductor",
	}
	for code, want := range cases {
		if got := jep106[code]; got != want {
			t.Errorf("jep106[0x%X] = %q; want %q", code, got, want)
		}
	}
}

// TestPartNamesARMJTAGDP cross-checks the ARM CoreSight family
// has its IDR entries.
func TestPartNamesARMJTAGDP(t *testing.T) {
	if name := partNames[0x23B][0xBA00]; name != "ARM Cortex-M JTAG-DP" {
		t.Errorf("partNames[ARM][0xBA00] = %q", name)
	}
	if name := partNames[0x23B][0xBA01]; !strings.HasPrefix(name, "ARM Cortex-A") {
		t.Errorf("partNames[ARM][0xBA01] = %q; want 'ARM Cortex-A...'", name)
	}
}
