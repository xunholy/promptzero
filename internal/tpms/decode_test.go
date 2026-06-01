// SPDX-License-Identifier: AGPL-3.0-or-later

package tpms

import (
	"strings"
	"testing"
)

// encodeManchester now lives in synth.go (production) — the decode and
// analyze round-trip tests share that single implementation.

// TestDecode_RoundTripIEEE encodes a payload whose last byte is a valid
// CRC-8/0x07 and asserts the decoder recovers the bytes, sensor ID,
// convention, and CRC match.
func TestDecode_RoundTripIEEE(t *testing.T) {
	data := []byte{0x1A, 0x2B, 0x3C, 0x4D, 0x80, 0x55}
	payload := append(append([]byte{}, data...), crc8(data, 0x07))
	bits := encodeManchester(payload, true)

	got, err := Decode(bits)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.HasPrefix(got.LineCoding, "Manchester (IEEE") {
		t.Errorf("LineCoding = %q; want IEEE", got.LineCoding)
	}
	wantHex := "1A2B3C4D8055" + hexByte(crc8(data, 0x07))
	if got.DecodedHex != wantHex {
		t.Errorf("DecodedHex = %q; want %q", got.DecodedHex, wantHex)
	}
	if got.SensorID != "1A2B3C4D" {
		t.Errorf("SensorID = %q; want 1A2B3C4D", got.SensorID)
	}
	if got.SensorIDDecimal == nil || *got.SensorIDDecimal != 0x1A2B3C4D {
		t.Errorf("SensorIDDecimal = %v; want 0x1A2B3C4D", got.SensorIDDecimal)
	}
	if !containsStr(got.CRC8Matches, "CRC-8/0x07") {
		t.Errorf("CRC8Matches = %v; want to contain CRC-8/0x07", got.CRC8Matches)
	}
}

// TestDecode_RoundTripGEThomas verifies the other Manchester
// convention is detected and decoded.
func TestDecode_RoundTripGEThomas(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x12}
	payload := append(append([]byte{}, data...), crc8(data, 0x2F))
	bits := encodeManchester(payload, false)

	got, err := Decode(bits)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.HasPrefix(got.LineCoding, "Manchester (G.E. Thomas") {
		t.Errorf("LineCoding = %q; want G.E. Thomas", got.LineCoding)
	}
	if got.SensorID != "DEADBEEF" {
		t.Errorf("SensorID = %q; want DEADBEEF", got.SensorID)
	}
	if !containsStr(got.CRC8Matches, "CRC-8/0x2F") {
		t.Errorf("CRC8Matches = %v; want CRC-8/0x2F", got.CRC8Matches)
	}
}

// TestDecode_IllegalPairStopsCleanly feeds a stream with an illegal
// "11" Manchester transition partway through; the decoder must return
// the clean prefix without panicking.
func TestDecode_IllegalPairStopsCleanly(t *testing.T) {
	data := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	bits := encodeManchester(data, true) + "1111" + "0101"
	got, err := Decode(bits)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// The clean prefix is the 4 encoded bytes (illegal pair halts there).
	if got.DecodedBytes < 4 {
		t.Errorf("DecodedBytes = %d; want >= 4", got.DecodedBytes)
	}
	if !strings.HasPrefix(got.DecodedHex, "AABBCCDD") {
		t.Errorf("DecodedHex = %q; want AABBCCDD prefix", got.DecodedHex)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":      "",
		"separators": " : - _ ",
		"non-binary": "0102",
		"too short":  "0101", // decodes to 2 bits, < 8 minimum
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// TestCRC8KnownVector pins crc8 against the standard CRC-8/SMBUS
// (poly 0x07, init 0x00) check value: "123456789" → 0xF4.
func TestCRC8KnownVector(t *testing.T) {
	if got := crc8([]byte("123456789"), 0x07); got != 0xF4 {
		t.Errorf("crc8(\"123456789\", 0x07) = 0x%02X; want 0xF4", got)
	}
}

func hexByte(b byte) string {
	const h = "0123456789ABCDEF"
	return string([]byte{h[b>>4], h[b&0x0F]})
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
