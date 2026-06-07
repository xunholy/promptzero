// SPDX-License-Identifier: AGPL-3.0-or-later

package jablotron

import "testing"

func TestDecodeValidBCD(t *testing.T) {
	// Constructed from the spec (independently verified): card bytes
	// 12 34 56 78 90 -> printed 1234567890, checksum (sum XOR 0x3A) = 0x9E.
	r, err := Decode("ffff12345678909e")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CardID != 1234567890 || !r.CardIDIsBCD {
		t.Errorf("CardID=%d isBCD=%v, want 1234567890/true", r.CardID, r.CardIDIsBCD)
	}
	if r.RawCardHex != "1234567890" {
		t.Errorf("RawCardHex=%q", r.RawCardHex)
	}
	if !r.CRCValid || r.CRC != "0x9E" {
		t.Errorf("CRC=%s valid=%v, want 0x9E/true", r.CRC, r.CRCValid)
	}
}

func TestDecodeNonBCD(t *testing.T) {
	// card bytes 00 01 B6 69 01 contain nibble 0xB (>9): valid checksum but the
	// BCD printed-number render is flagged not-meaningful; raw value relied on.
	r, err := Decode("ffff0001b669011b")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.CRCValid {
		t.Errorf("CRC should be valid (0x1B)")
	}
	if r.CardIDIsBCD {
		t.Errorf("expected CardIDIsBCD=false for non-BCD card data")
	}
	if r.RawCard40 != 0x0001B66901 {
		t.Errorf("RawCard40=%d, want %d", r.RawCard40, 0x0001B66901)
	}
}

func TestChecksumMismatch(t *testing.T) {
	// Valid block with the checksum byte corrupted: structurally Jablotron but
	// the integrity check must fail and be reported.
	r, err := Decode("ffff12345678909f") // crc 0x9F instead of 0x9E
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CRCValid {
		t.Errorf("expected CRC invalid (exp %s)", r.CRCExpected)
	}
	if len(r.Notes) == 0 {
		t.Errorf("expected a mismatch note")
	}
}

func TestStructuralRejection(t *testing.T) {
	// Missing 0xFFFF preamble must be rejected, not mis-decoded.
	if _, err := Decode("0000123456789012"); err == nil {
		t.Errorf("expected rejection of a frame without the 0xFFFF preamble")
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz", "ffff12", "ffff12345678909e00"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
