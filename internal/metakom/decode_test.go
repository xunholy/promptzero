// SPDX-License-Identifier: AGPL-3.0-or-later

package metakom

import "testing"

func TestDecodeValidParity(t *testing.T) {
	// Each byte has an even number of 1 bits: 0x03=2, 0x0F=4, 0x33=4, 0xC3=4.
	r, err := Decode("030F33C3")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.ParityValid {
		t.Errorf("expected parity valid, byteParity=%v", r.ByteParity)
	}
	if r.IDHex != "030F33C3" || r.ID != "03 0F 33 C3" {
		t.Errorf("ID=%q / %q", r.IDHex, r.ID)
	}
}

func TestDecodeInvalidParity(t *testing.T) {
	// byte 0 = 0x01 has one 1 bit (odd) -> invalid.
	r, err := Decode("010F33C3")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ParityValid {
		t.Errorf("expected parity invalid")
	}
	if r.ByteParity[0] {
		t.Errorf("byte 0 (0x01) should be odd parity (false)")
	}
	if !r.ByteParity[1] {
		t.Errorf("byte 1 (0x0F) should be even parity (true)")
	}
}

func TestDecodeAllZero(t *testing.T) {
	// 0x00 has zero 1 bits (even) -> all valid.
	r, err := Decode("00000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.ParityValid {
		t.Errorf("all-zero key should be parity-valid")
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz", "030F33", "030F33C3AA"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
