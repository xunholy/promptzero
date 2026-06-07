// SPDX-License-Identifier: AGPL-3.0-or-later

package noralsy

import "testing"

func TestDecodeValid(t *testing.T) {
	// Constructed from the spec (independently verified): card 1234567, year 2021.
	r, err := Decode("bb0214ff1232104567370000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CardIDHex != "1234567" || r.CardIDPacked != 0x1234567 {
		t.Errorf("card hex=%q packed=0x%X", r.CardIDHex, r.CardIDPacked)
	}
	if !r.CardIDIsBCD || r.CardIDBCD != 1234567 {
		t.Errorf("card BCD=%d isBCD=%v, want 1234567/true", r.CardIDBCD, r.CardIDIsBCD)
	}
	if r.Year != 2021 {
		t.Errorf("year=%d, want 2021", r.Year)
	}
	if !r.Chk1Valid || !r.Chk2Valid {
		t.Errorf("checksums should be valid: chk1=%v chk2=%v", r.Chk1Valid, r.Chk2Valid)
	}
}

func TestYear19xx(t *testing.T) {
	// year BCD 0x99 = 99 (>60) -> 1999.
	r, err := Decode("bb0214ff0009900001170000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Year != 1999 {
		t.Errorf("year=%d, want 1999", r.Year)
	}
	if !r.Chk1Valid || !r.Chk2Valid {
		t.Errorf("checksums should be valid")
	}
}

func TestNonBCDCard(t *testing.T) {
	// card nibbles exceed 9 (0xABCDEF0): BCD render omitted, hex relied upon.
	r, err := Decode("bb0214ffabc210def0270000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CardIDIsBCD {
		t.Errorf("expected CardIDIsBCD=false")
	}
	if r.CardIDBCD != 0 {
		t.Errorf("expected CardIDBCD omitted (0) for non-BCD, got %d", r.CardIDBCD)
	}
	if r.CardIDHex != "ABCDEF0" {
		t.Errorf("CardIDHex=%q, want ABCDEF0", r.CardIDHex)
	}
}

func TestChecksumMismatch(t *testing.T) {
	// Correct preamble but corrupt a card byte without fixing the checksums.
	r, err := Decode("bb0214ff1232104566370000") // low byte 0x67 -> 0x66
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Chk1Valid && r.Chk2Valid {
		t.Errorf("expected at least one checksum invalid after corruption")
	}
}

func TestStructuralRejection(t *testing.T) {
	// Wrong preamble must be rejected.
	if _, err := Decode("bb0214fe1232104567370000"); err == nil {
		t.Errorf("expected rejection of a frame without the 0xBB0214FF preamble")
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz", "bb0214ff", "bb0214ff123210456737000000"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
