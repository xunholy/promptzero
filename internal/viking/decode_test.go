// SPDX-License-Identifier: AGPL-3.0-or-later

package viking

import "testing"

func TestDecodeVectors(t *testing.T) {
	// Constructed from the spec (independently verified): preamble F20000 +
	// 32-bit card ID + checksum making XOR(all 8 bytes) == 0xA8.
	cases := []struct {
		hex    string
		cardID uint32
		crc    string
	}{
		{"f200000001a337cf", 0x0001A337, "0xCF"}, // help-text card number 01A337
		{"f200001234567852", 0x12345678, "0x52"},
		{"f20000000000015b", 0x00000001, "0x5B"},
	}
	for _, c := range cases {
		r, err := Decode(c.hex)
		if err != nil {
			t.Fatalf("Decode(%s): %v", c.hex, err)
		}
		if r.CardID != c.cardID {
			t.Errorf("%s: CardID=0x%08X, want 0x%08X", c.hex, r.CardID, c.cardID)
		}
		if !r.CRCValid || r.CRC != c.crc {
			t.Errorf("%s: CRC=%s valid=%v, want %s/true", c.hex, r.CRC, r.CRCValid, c.crc)
		}
	}
}

func TestCardIDHex(t *testing.T) {
	r, err := Decode("f200000001a337cf")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CardIDHex != "0001A337" {
		t.Errorf("CardIDHex=%q, want 0001A337", r.CardIDHex)
	}
}

func TestChecksumMismatch(t *testing.T) {
	// Valid block with the checksum byte corrupted: XOR(all) != 0xA8.
	r, err := Decode("f200000001a337ce") // crc 0xCE instead of 0xCF
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
	// Wrong preamble must be rejected, not mis-decoded.
	if _, err := Decode("f100000001a337cf"); err == nil {
		t.Errorf("expected rejection of a frame without the F20000 preamble")
	}
	if _, err := Decode("f200ff0001a337cf"); err == nil {
		t.Errorf("expected rejection of a frame with non-zero preamble bytes")
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz", "f20000", "f200000001a337cf00"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
