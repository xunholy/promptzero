package pacs

import (
	"strings"
	"testing"
)

func TestDecodeBits_H10301_Canonical(t *testing.T) {
	// HID H10301 26-bit, FC=123, CN=45678.
	// Layout: P + 8 FC + 16 CN + P.
	// FC=123=01111011, CN=45678=1011001001101110.
	// Data bits 1-12: "011110111011" = 9 ones (odd) → P0=1
	// to round to even. Data bits 13-24: "001001101110" = 6
	// ones (even) → odd parity P25=1.
	bits := "10111101110110010011011101"
	r, err := DecodeBits(bits)
	if err != nil {
		t.Fatalf("DecodeBits: %v", err)
	}
	if r.BitLength != 26 || len(r.Candidates) != 1 {
		t.Fatalf("bit_length=%d candidates=%d", r.BitLength, len(r.Candidates))
	}
	c := r.Candidates[0]
	if c.Format != "HID H10301 26-bit" {
		t.Errorf("format: %q", c.Format)
	}
	if c.FacilityCode != 123 || c.CardNumber != 45678 {
		t.Errorf("FC=%d CN=%d (want 123 / 45678)", c.FacilityCode, c.CardNumber)
	}
	if !c.ParityValid {
		t.Errorf("parity_valid should be true: %s", c.ParityNotes)
	}
}

func TestDecodeBits_H10306_Canonical(t *testing.T) {
	// HID H10306 34-bit, FC=999, CN=12345.
	bits := "0000000111110011100110000001110011"
	r, err := DecodeBits(bits)
	if err != nil {
		t.Fatalf("DecodeBits: %v", err)
	}
	if r.BitLength != 34 {
		t.Fatalf("bit_length: %d", r.BitLength)
	}
	c := r.Candidates[0]
	if c.Format != "HID H10306 34-bit" {
		t.Errorf("format: %q", c.Format)
	}
	if c.FacilityCode != 999 || c.CardNumber != 12345 {
		t.Errorf("FC=%d CN=%d (want 999 / 12345)", c.FacilityCode, c.CardNumber)
	}
	if !c.ParityValid {
		t.Errorf("parity_valid should be true: %s", c.ParityNotes)
	}
}

func TestDecodeBits_H10301_BrokenParity(t *testing.T) {
	// Same H10301 vector but with P0 flipped (was 1, now 0).
	// FC/CN still decode but parity_valid is false.
	bits := "00111101110110010011011101"
	r, err := DecodeBits(bits)
	if err != nil {
		t.Fatalf("DecodeBits: %v", err)
	}
	c := r.Candidates[0]
	if c.FacilityCode != 123 || c.CardNumber != 45678 {
		t.Errorf("FC/CN should still decode: %d / %d", c.FacilityCode, c.CardNumber)
	}
	if c.ParityValid {
		t.Errorf("parity_valid should be false")
	}
}

func TestDecodeBits_37bit_ReturnsBothCandidates(t *testing.T) {
	// A 37-bit vector matches both H10304 and H10302 — the
	// decoder surfaces both candidates and lets the caller
	// pick by parity validity or facility-code sanity.
	// Construct an H10302 vector with CN=12345 (35-bit).
	// 12345 in 35-bit binary: 21 zeros + 11000000111001.
	// Even parity bit 0 over bits 1-18 = "000000000000000000" (0 ones, even) → P0=0.
	// Odd parity bit 36 over bits 18-35 = "000011000000111001" (6 ones, even) → P36=1.
	bits := "0000000000000000000000110000001110011"
	r, err := DecodeBits(bits)
	if err != nil {
		t.Fatalf("DecodeBits: %v", err)
	}
	if r.BitLength != 37 {
		t.Fatalf("bit_length: %d", r.BitLength)
	}
	if len(r.Candidates) != 2 {
		t.Fatalf("expected 2 candidates for 37-bit, got %d", len(r.Candidates))
	}
	var sawH10302 bool
	for _, c := range r.Candidates {
		if strings.Contains(c.Format, "H10302") {
			sawH10302 = true
			if c.CardNumber != 12345 {
				t.Errorf("H10302 CN: %d", c.CardNumber)
			}
			if !c.ParityValid {
				t.Errorf("H10302 parity: %s", c.ParityNotes)
			}
		}
	}
	if !sawH10302 {
		t.Errorf("expected H10302 candidate in: %+v", r.Candidates)
	}
}

func TestDecodeBits_UnknownLength_StillReturnsBits(t *testing.T) {
	// 30 bits doesn't match any catalogued format — we return
	// the bits + a note, no candidates.
	bits := "000000000000000000000000000000"
	r, err := DecodeBits(bits)
	if err != nil {
		t.Fatalf("DecodeBits: %v", err)
	}
	if r.BitLength != 30 || len(r.Candidates) != 0 {
		t.Errorf("bit_length=%d candidates=%d", r.BitLength, len(r.Candidates))
	}
	if len(r.Notes) == 0 {
		t.Error("expected a note for unknown bit length")
	}
}

func TestDecodeBits_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"invalid":            "01010X01",
		"whitespace+invalid": "010 102",
	}
	for name, in := range cases {
		_, err := DecodeBits(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestDecodeHex_H10301_FromHex(t *testing.T) {
	// Same H10301 vector as the canonical test, expressed as
	// hex + bit_length 26.
	// Bits: "10111101110110010011011101"
	// Padded to 32 (last 6 bits zero):
	// "10111101110110010011011101000000"
	// Bytes: 10111101 11011001 00110111 01000000 = 0xBD D9 37 40.
	r, err := DecodeHex("BDD93740", 26)
	if err != nil {
		t.Fatalf("DecodeHex: %v", err)
	}
	if len(r.Candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(r.Candidates))
	}
	c := r.Candidates[0]
	if c.FacilityCode != 123 || c.CardNumber != 45678 {
		t.Errorf("FC=%d CN=%d", c.FacilityCode, c.CardNumber)
	}
	if !c.ParityValid {
		t.Errorf("parity_valid should be true")
	}
}

func TestDecodeHex_Rejections(t *testing.T) {
	if _, err := DecodeHex("", 26); err == nil {
		t.Error("empty hex should error")
	}
	if _, err := DecodeHex("3DD93740", 0); err == nil {
		t.Error("bit_length 0 should error")
	}
	if _, err := DecodeHex("ZZ", 8); err == nil {
		t.Error("invalid hex should error")
	}
	if _, err := DecodeHex("AA", 100); err == nil {
		t.Error("bit_length exceeding capacity should error")
	}
	if _, err := DecodeHex("AAA", 8); err == nil {
		t.Error("odd hex length should error")
	}
}

func TestBitsToHexAndBack(t *testing.T) {
	// Round-trip a 26-bit value through bitsToHex.
	bits := "10111101110110010011011101"
	h := bitsToHex(bits)
	want := "BDD93740"
	if h != want {
		t.Errorf("bitsToHex: got %q want %q", h, want)
	}
}
