package btclassic

import (
	"strings"
	"testing"
)

// TestDecode_SmartphoneCoD pins a "smart phone" Class of Device
// value built from the documented bit positions:
//
//	bits 23..13 = service classes (Telephony bit 22 + Object Transfer bit 20)
//	bits 12..8 = major class = 2 (Phone)
//	bits 7..2 = minor class identifier = 3 (Smart Phone)
//	bits 1..0 = format type = 0
//
// = (1<<22) | (1<<20) | (2<<8) | (3<<2)
// = 0x400000 | 0x100000 | 0x0200 | 0x000C
// = 0x50020C
func TestDecode_SmartphoneCoD(t *testing.T) {
	got := DecodeUint24(0x50020C)
	if got.MajorClassName != "Phone" {
		t.Errorf("MajorClassName = %q; want 'Phone'", got.MajorClassName)
	}
	if got.MinorClassName != "Smart phone" {
		t.Errorf("MinorClassName = %q; want 'Smart phone'", got.MinorClassName)
	}
	if got.FormatType != 0 {
		t.Errorf("FormatType = %d; want 0", got.FormatType)
	}
	if !contains(got.ServiceClasses, "Telephony") {
		t.Errorf("ServiceClasses missing Telephony: %v", got.ServiceClasses)
	}
	if !contains(got.ServiceClasses, "Object Transfer") {
		t.Errorf("ServiceClasses missing Object Transfer: %v", got.ServiceClasses)
	}
}

// TestDecode_LaptopCoD pins a Laptop CoD:
//
//	major = 1 (Computer), minor = 3 (Laptop)
//	services: Networking (bit 17) + Object Transfer (bit 20)
//
// CoD = (1<<20) | (1<<17) | (1<<8) | (3<<2)
// = 0x100000 | 0x020000 | 0x0100 | 0x000C = 0x12010C
func TestDecode_LaptopCoD(t *testing.T) {
	got := DecodeUint24(0x12010C)
	if got.MajorClassName != "Computer" {
		t.Errorf("MajorClassName = %q", got.MajorClassName)
	}
	if got.MinorClassName != "Laptop" {
		t.Errorf("MinorClassName = %q; want 'Laptop'", got.MinorClassName)
	}
	if !contains(got.ServiceClasses, "Networking") {
		t.Errorf("ServiceClasses missing Networking: %v", got.ServiceClasses)
	}
}

// TestDecode_AudioHeadphones pins a Headphones CoD:
//
//	major = 4 (Audio/Video), minor = 6 (Headphones)
//	services: Audio (bit 21) + Rendering (bit 18)
//
// CoD = (1<<21) | (1<<18) | (4<<8) | (6<<2)
// = 0x200000 | 0x040000 | 0x0400 | 0x0018 = 0x240418
func TestDecode_AudioHeadphones(t *testing.T) {
	got := DecodeUint24(0x240418)
	if got.MajorClassName != "Audio / Video" {
		t.Errorf("MajorClassName = %q", got.MajorClassName)
	}
	if got.MinorClassName != "Headphones" {
		t.Errorf("MinorClassName = %q; want 'Headphones'", got.MinorClassName)
	}
	if !contains(got.ServiceClasses, "Audio") {
		t.Errorf("ServiceClasses missing Audio: %v", got.ServiceClasses)
	}
	if !contains(got.ServiceClasses, "Rendering") {
		t.Errorf("ServiceClasses missing Rendering: %v", got.ServiceClasses)
	}
}

// TestDecode_PeripheralKeyboardMouse pins a Peripheral with
// both keyboard + pointing-device flags set in the minor field:
//
//	major = 5 (Peripheral) → bits 12..8 = 00101
//	minor = bit 5 (kb) + bit 4 (pointing) = 0x30 → bits 7..2 of CoD
//
// CoD = (5 << 8) | (0x30 << 2) = 0x500 | 0xC0 = 0x0005C0
func TestDecode_PeripheralKeyboardMouse(t *testing.T) {
	got := DecodeUint24(0x0005C0)
	if got.MajorClassName != "Peripheral" {
		t.Errorf("MajorClassName = %q; want 'Peripheral'", got.MajorClassName)
	}
	if !strings.Contains(got.MinorClassName, "keyboard") ||
		!strings.Contains(got.MinorClassName, "pointing") {
		t.Errorf("MinorClassName = %q; want it to mention keyboard + pointing",
			got.MinorClassName)
	}
}

// TestDecode_HealthThermometer pins a Health Major + Thermometer
// Minor:
//
//	major = 9 (Health), minor = 2 (Thermometer)
//
// CoD = (9<<8) | (2<<2) = 0x0900 | 0x08 = 0x000908
func TestDecode_HealthThermometer(t *testing.T) {
	got := DecodeUint24(0x000908)
	if got.MajorClassName != "Health" {
		t.Errorf("MajorClassName = %q", got.MajorClassName)
	}
	if got.MinorClassName != "Thermometer" {
		t.Errorf("MinorClassName = %q", got.MinorClassName)
	}
}

// TestDecode_UncategorizedMajor handles Major Class 0x1F.
func TestDecode_UncategorizedMajor(t *testing.T) {
	got := DecodeUint24(0x001F00)
	if got.MajorClassName != "Uncategorized" {
		t.Errorf("MajorClassName = %q", got.MajorClassName)
	}
}

// TestDecode_HexInput exercises the string-input parser with
// '0x' prefix and separators.
func TestDecode_HexInput(t *testing.T) {
	got, err := Decode("0x5A020C")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MajorClassName != "Phone" {
		t.Errorf("MajorClassName = %q", got.MajorClassName)
	}
}

// TestDecode_Separators — ':' / '-' / '_' / whitespace.
func TestDecode_Separators(t *testing.T) {
	for _, in := range []string{
		"5A:02:0C",
		"5A-02-0C",
		"5A_02_0C",
		" 5A 02 0C ",
	} {
		got, err := Decode(in)
		if err != nil {
			t.Errorf("Decode(%q): %v", in, err)
			continue
		}
		if got.MajorClassName != "Phone" {
			t.Errorf("Decode(%q): MajorClassName = %q", in, got.MajorClassName)
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

// TestDecode_FormatTypeReserved — bits 1..0 != 00 are reserved
// by the spec; we surface the value but don't error.
func TestDecode_FormatTypeReserved(t *testing.T) {
	// CoD = 0x000003 → FormatType = 3 (reserved)
	got := DecodeUint24(0x000003)
	if got.FormatType != 3 {
		t.Errorf("FormatType = %d; want 3", got.FormatType)
	}
}

// TestMajorClassName spot-checks the table.
func TestMajorClassName(t *testing.T) {
	cases := map[int]string{
		0:    "Miscellaneous",
		1:    "Computer",
		2:    "Phone",
		4:    "Audio / Video",
		5:    "Peripheral",
		7:    "Wearable",
		9:    "Health",
		0x1F: "Uncategorized",
	}
	for m, want := range cases {
		if got := majorClassName(m); got != want {
			t.Errorf("majorClassName(%d) = %q; want %q", m, got, want)
		}
	}
}

// TestDecode_ServiceClassesAllSet — every documented service
// class bit set (bits 13, 14, 16, 17, 18, 19, 20, 21, 22, 23 —
// bit 15 is reserved).
//
// = (1<<13)|(1<<14)|(1<<16)|(1<<17)|(1<<18)|(1<<19)|(1<<20)|
//
//	(1<<21)|(1<<22)|(1<<23)
//
// = 0x002000 | 0x004000 | 0x010000 | 0x020000 | 0x040000 |
//
//	0x080000 | 0x100000 | 0x200000 | 0x400000 | 0x800000
//
// = 0xFF6000
func TestDecode_ServiceClassesAllSet(t *testing.T) {
	got := DecodeUint24(0xFF6000)
	want := []string{
		"Limited Discoverable Mode",
		"LE audio",
		"Positioning",
		"Networking",
		"Rendering",
		"Capturing",
		"Object Transfer",
		"Audio",
		"Telephony",
		"Information",
	}
	if len(got.ServiceClasses) != len(want) {
		t.Errorf("ServiceClasses count = %d; want %d\ngot: %v",
			len(got.ServiceClasses), len(want), got.ServiceClasses)
	}
	for _, w := range want {
		if !contains(got.ServiceClasses, w) {
			t.Errorf("ServiceClasses missing %q: %v", w, got.ServiceClasses)
		}
	}
}

// contains is a small test helper for substring lookup.
func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
