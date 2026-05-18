package zigbee

import (
	"testing"
)

// TestDecodeAttribute_Boolean pins boolean type (0x10).
func TestDecodeAttribute_Boolean(t *testing.T) {
	gotTrue, n, err := DecodeAttribute("10 01")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if n != 2 {
		t.Errorf("bytes consumed = %d; want 2", n)
	}
	if gotTrue.Value != true {
		t.Errorf("Value = %v; want true", gotTrue.Value)
	}
	if gotTrue.TypeName != "Boolean" {
		t.Errorf("TypeName = %q", gotTrue.TypeName)
	}
	// false case
	gotFalse, _, _ := DecodeAttribute("10 00")
	if gotFalse.Value != false {
		t.Errorf("Value = %v; want false", gotFalse.Value)
	}
}

// TestDecodeAttribute_Uint8 pins uint8 (0x20).
func TestDecodeAttribute_Uint8(t *testing.T) {
	got, n, err := DecodeAttribute("20 FF")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if n != 2 {
		t.Errorf("bytes consumed = %d", n)
	}
	if got.Value != int64(255) {
		t.Errorf("Value = %v; want 255", got.Value)
	}
}

// TestDecodeAttribute_Uint16 pins uint16 (0x21) with
// little-endian wire encoding.
func TestDecodeAttribute_Uint16(t *testing.T) {
	// 0x1234 LE = 34 12
	got, n, err := DecodeAttribute("21 34 12")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if n != 3 {
		t.Errorf("bytes consumed = %d", n)
	}
	if got.Value != int64(0x1234) {
		t.Errorf("Value = %v; want 0x1234", got.Value)
	}
}

// TestDecodeAttribute_Int16 pins int16 (0x29) with negative
// value.
func TestDecodeAttribute_Int16(t *testing.T) {
	// -100 = 0xFF9C LE = 9C FF
	got, _, err := DecodeAttribute("29 9C FF")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Value != int64(-100) {
		t.Errorf("Value = %v; want -100", got.Value)
	}
}

// TestDecodeAttribute_Int8 pins int8 (0x28) with negative.
func TestDecodeAttribute_Int8(t *testing.T) {
	// -1 = 0xFF
	got, _, err := DecodeAttribute("28 FF")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Value != int64(-1) {
		t.Errorf("Value = %v; want -1", got.Value)
	}
}

// TestDecodeAttribute_Float32 pins single-precision float (0x39).
func TestDecodeAttribute_Float32(t *testing.T) {
	// 1.5 = 0x3FC00000 LE = 00 00 C0 3F
	got, _, err := DecodeAttribute("39 00 00 C0 3F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Value != float64(1.5) {
		t.Errorf("Value = %v; want 1.5", got.Value)
	}
}

// TestDecodeAttribute_CharString pins char string (0x42).
func TestDecodeAttribute_CharString(t *testing.T) {
	// Length 5 + "hello" (68 65 6C 6C 6F)
	got, n, err := DecodeAttribute("42 05 68 65 6C 6C 6F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if n != 7 {
		t.Errorf("bytes consumed = %d", n)
	}
	if got.Value != "hello" {
		t.Errorf("Value = %v; want 'hello'", got.Value)
	}
}

// TestDecodeAttribute_OctetString pins octet string (0x41).
func TestDecodeAttribute_OctetString(t *testing.T) {
	// Length 3 + AA BB CC
	got, _, err := DecodeAttribute("41 03 AA BB CC")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Value != "AABBCC" {
		t.Errorf("Value = %v; want 'AABBCC'", got.Value)
	}
}

// TestDecodeAttribute_LongCharString pins long char string
// (0x44) — 2-byte length prefix.
func TestDecodeAttribute_LongCharString(t *testing.T) {
	// Length 3 LE = 03 00, then "Foo"
	got, _, err := DecodeAttribute("44 03 00 46 6F 6F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Value != "Foo" {
		t.Errorf("Value = %v; want 'Foo'", got.Value)
	}
}

// TestDecodeAttribute_IEEEAddress pins IEEE address (0xF0,
// 8 bytes LE on wire, BE rendered).
func TestDecodeAttribute_IEEEAddress(t *testing.T) {
	// LE wire 08 07 06 05 04 03 02 01 → BE "0102030405060708"
	got, _, err := DecodeAttribute("F0 08 07 06 05 04 03 02 01")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Value != "0102030405060708" {
		t.Errorf("Value = %v; want '0102030405060708'", got.Value)
	}
}

// TestDecodeAttribute_TimeOfDay pins time-of-day formatting.
func TestDecodeAttribute_TimeOfDay(t *testing.T) {
	// 14:35:42.50 = 0E 23 2A 32
	got, _, err := DecodeAttribute("E0 0E 23 2A 32")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Value != "14:35:42.50" {
		t.Errorf("Value = %v; want '14:35:42.50'", got.Value)
	}
}

// TestDecodeAttribute_ClusterID pins cluster-ID (0xE8).
func TestDecodeAttribute_ClusterID(t *testing.T) {
	// 0x0006 (On/Off) LE = 06 00
	got, _, err := DecodeAttribute("E8 06 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Value != "0006" {
		t.Errorf("Value = %v; want '0006'", got.Value)
	}
}

// TestDecodeAttribute_NoData pins the no-data type (0x00).
func TestDecodeAttribute_NoData(t *testing.T) {
	got, n, err := DecodeAttribute("00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if n != 1 {
		t.Errorf("bytes consumed = %d; want 1 (type byte only)", n)
	}
	if got.Value != nil {
		t.Errorf("Value = %v; want nil", got.Value)
	}
	if got.TypeName != "No data" {
		t.Errorf("TypeName = %q", got.TypeName)
	}
}

// TestDecodeAttribute_Bitmap8 pins 8-bit bitmap (0x18).
func TestDecodeAttribute_Bitmap8(t *testing.T) {
	got, _, err := DecodeAttribute("18 AA")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Value != int64(0xAA) {
		t.Errorf("Value = %v", got.Value)
	}
}

// TestDecodeAttribute_Uint32 pins uint32 (0x23).
func TestDecodeAttribute_Uint32(t *testing.T) {
	// 0xDEADBEEF LE = EF BE AD DE
	got, _, err := DecodeAttribute("23 EF BE AD DE")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Value != int64(0xDEADBEEF) {
		t.Errorf("Value = 0x%X; want 0xDEADBEEF", got.Value)
	}
}

// TestDecodeAttribute_Enum8 pins 8-bit enum (0x30).
func TestDecodeAttribute_Enum8(t *testing.T) {
	got, _, err := DecodeAttribute("30 05")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Value != int64(5) {
		t.Errorf("Value = %v", got.Value)
	}
	if got.TypeName != "8-bit enumeration" {
		t.Errorf("TypeName = %q", got.TypeName)
	}
}

// TestDecodeAttribute_TruncatedUint16 — uint16 with only 1
// byte of data → error.
func TestDecodeAttribute_TruncatedUint16(t *testing.T) {
	_, _, err := DecodeAttribute("21 12")
	if err == nil {
		t.Fatal("want error for truncated uint16")
	}
}

// TestDecodeAttribute_UnknownType — type 0x99 not in the
// catalog → error.
func TestDecodeAttribute_UnknownType(t *testing.T) {
	_, _, err := DecodeAttribute("99 AA BB")
	if err == nil {
		t.Fatal("want error for unknown type")
	}
}

// TestDecodeAttribute_EmptyInput — empty input → error.
func TestDecodeAttribute_EmptyInput(t *testing.T) {
	if _, _, err := DecodeAttribute(""); err == nil {
		t.Error("empty input: want error")
	}
}

// TestAttributeTypeName spot-checks the type-name table.
func TestAttributeTypeName(t *testing.T) {
	cases := map[byte]string{
		0x10: "Boolean",
		0x20: "uint8",
		0x29: "int16",
		0x39: "Single-precision float (32-bit)",
		0x42: "Character string",
		0xF0: "IEEE address",
	}
	for code, want := range cases {
		if got := attributeTypeName(code); got != want {
			t.Errorf("attributeTypeName(0x%02X) = %q; want %q", code, got, want)
		}
	}
}

// TestFloat16ToFloat64 spot-checks the half-float decoder.
func TestFloat16ToFloat64(t *testing.T) {
	cases := map[uint16]float64{
		0x0000: 0.0,
		0x3C00: 1.0,
		0x4000: 2.0,
		0xBC00: -1.0,
	}
	for in, want := range cases {
		if got := float16ToFloat64(in); got != want {
			t.Errorf("float16ToFloat64(0x%04X) = %v; want %v", in, got, want)
		}
	}
}
