// SPDX-License-Identifier: AGPL-3.0-or-later

package obd2

import "testing"

// TestDecodeDTC_HandVectors checks the J2012 bit-unpack against published
// trouble codes spanning all four categories and both control classes.
func TestDecodeDTC_HandVectors(t *testing.T) {
	cases := []struct {
		a, b byte
		code string
		cat  string
	}{
		{0x01, 0x43, "P0143", "Powertrain"},
		{0x04, 0x20, "P0420", "Powertrain"},
		{0x03, 0x00, "P0300", "Powertrain"},
		{0xC1, 0x23, "U0123", "Network"},
		{0x81, 0x65, "B0165", "Body"},
		{0x42, 0x35, "C0235", "Chassis"},
		{0x11, 0x28, "P1128", "Powertrain"}, // first digit 1 = manufacturer-specific
	}
	for _, c := range cases {
		d := DecodeDTC(c.a, c.b)
		if d.Code != c.code {
			t.Errorf("DecodeDTC(0x%02X,0x%02X) = %s, want %s", c.a, c.b, d.Code, c.code)
		}
		if d.Category != c.cat {
			t.Errorf("%s category = %s, want %s", c.code, d.Category, c.cat)
		}
	}
}

func TestDecodeDTC_GenericVsManufacturer(t *testing.T) {
	gen := DecodeDTC(0x01, 0x43) // P0143, first digit 0
	if !gen.Generic || gen.ManufacturerSpecific {
		t.Errorf("P0143 generic=%v mfr=%v, want true/false", gen.Generic, gen.ManufacturerSpecific)
	}
	mfr := DecodeDTC(0x11, 0x28) // P1128, first digit 1
	if mfr.Generic || !mfr.ManufacturerSpecific {
		t.Errorf("P1128 generic=%v mfr=%v, want false/true", mfr.Generic, mfr.ManufacturerSpecific)
	}
}

func TestDecodeDTCResponse_WithServiceByte(t *testing.T) {
	// 43 (Mode 03) + P0143 + P0420
	r, err := DecodeDTCResponse("43 0143 0420")
	if err != nil {
		t.Fatalf("DecodeDTCResponse: %v", err)
	}
	if r.Mode != 0x43 || r.ModeName == "" {
		t.Errorf("mode = 0x%02X (%q)", r.Mode, r.ModeName)
	}
	if r.Count != 2 {
		t.Fatalf("count = %d, want 2", r.Count)
	}
	if r.DTCs[0].Code != "P0143" || r.DTCs[1].Code != "P0420" {
		t.Errorf("codes = %s,%s want P0143,P0420", r.DTCs[0].Code, r.DTCs[1].Code)
	}
}

func TestDecodeDTCResponse_SkipsPadding(t *testing.T) {
	// bare stream: P0143 + 0000 padding + P0420
	r, err := DecodeDTCResponse("014300000420")
	if err != nil {
		t.Fatalf("DecodeDTCResponse: %v", err)
	}
	if r.Count != 2 {
		t.Errorf("count = %d, want 2 (padding skipped)", r.Count)
	}
}

func TestDecodeDTCResponse_NoFaults(t *testing.T) {
	r, err := DecodeDTCResponse("4700000000")
	if err != nil {
		t.Fatalf("DecodeDTCResponse: %v", err)
	}
	if r.Count != 0 {
		t.Errorf("count = %d, want 0", r.Count)
	}
	if r.Mode != 0x47 {
		t.Errorf("mode = 0x%02X, want 0x47", r.Mode)
	}
	if len(r.Notes) == 0 {
		t.Error("expected a no-faults note")
	}
}

func TestDecodeDTCResponse_OddBytes(t *testing.T) {
	// bare stream with a trailing odd byte.
	r, err := DecodeDTCResponse("014305")
	if err != nil {
		t.Fatalf("DecodeDTCResponse: %v", err)
	}
	if r.Count != 1 || r.DTCs[0].Code != "P0143" {
		t.Errorf("codes = %+v, want one P0143", r.DTCs)
	}
	if len(r.Notes) == 0 {
		t.Error("expected an odd-byte-count note")
	}
}

func TestDecodeDTCResponse_Errors(t *testing.T) {
	for _, in := range []string{"", "zz", "43"} { // empty, non-hex, service byte only
		if _, err := DecodeDTCResponse(in); err == nil {
			t.Errorf("DecodeDTCResponse(%q): expected error", in)
		}
	}
}
