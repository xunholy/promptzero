// SPDX-License-Identifier: AGPL-3.0-or-later

package wps

import "testing"

// TestChecksum_Canonical: checksum(1234567) = 0, so 12345670 is the
// canonical valid WPS PIN.
func TestChecksum_Canonical(t *testing.T) {
	if d := Checksum(1234567); d != 0 {
		t.Errorf("Checksum(1234567) = %d, want 0", d)
	}
	if d := Checksum(0); d != 0 {
		t.Errorf("Checksum(0) = %d, want 0 (00000000 valid)", d)
	}
}

func TestCheckPIN_ValidateCanonical(t *testing.T) {
	r, err := CheckPIN("12345670")
	if err != nil {
		t.Fatalf("CheckPIN: %v", err)
	}
	if r.Mode != "validate" || r.Valid == nil || !*r.Valid {
		t.Errorf("12345670 should be valid: %+v", r)
	}
	if r.WellKnown == "" {
		t.Error("12345670 should be flagged well-known")
	}
}

func TestCheckPIN_ValidateInvalid(t *testing.T) {
	// 12345671 has the wrong check digit (expected 0).
	r, err := CheckPIN("12345671")
	if err != nil {
		t.Fatalf("CheckPIN: %v", err)
	}
	if r.Valid == nil || *r.Valid {
		t.Errorf("12345671 should be invalid: %+v", r)
	}
	if r.ExpectedDigit == nil || *r.ExpectedDigit != 0 {
		t.Errorf("expected check digit 0, got %v", r.ExpectedDigit)
	}
	if r.Note == "" {
		t.Error("expected a note for the invalid PIN")
	}
}

func TestCheckPIN_Complete(t *testing.T) {
	r, err := CheckPIN("1234567")
	if err != nil {
		t.Fatalf("CheckPIN: %v", err)
	}
	if r.Mode != "complete" || r.FullPIN != "12345670" {
		t.Errorf("complete(1234567) = %s, want 12345670", r.FullPIN)
	}
	if r.ExpectedDigit == nil || *r.ExpectedDigit != 0 {
		t.Errorf("check digit = %v, want 0", r.ExpectedDigit)
	}
	if r.WellKnown == "" {
		t.Error("completed 12345670 should be flagged well-known")
	}
}

// TestCheckPIN_RoundTrip: completing any 7-digit prefix yields an 8-digit
// PIN that validates.
func TestCheckPIN_RoundTrip(t *testing.T) {
	for _, prefix := range []string{"0000000", "1111111", "9876543", "1357924", "0010203"} {
		c, err := CheckPIN(prefix)
		if err != nil {
			t.Fatalf("complete(%s): %v", prefix, err)
		}
		v, err := CheckPIN(c.FullPIN)
		if err != nil {
			t.Fatalf("validate(%s): %v", c.FullPIN, err)
		}
		if v.Valid == nil || !*v.Valid {
			t.Errorf("completed PIN %s did not validate", c.FullPIN)
		}
	}
}

func TestCheckPIN_Separators(t *testing.T) {
	r, err := CheckPIN("1234-5670")
	if err != nil {
		t.Fatalf("CheckPIN: %v", err)
	}
	if r.Valid == nil || !*r.Valid {
		t.Errorf("separated 12345670 should validate: %+v", r)
	}
}

func TestCheckPIN_Errors(t *testing.T) {
	for _, in := range []string{"", "123", "123456789", "12abc670"} {
		if _, err := CheckPIN(in); err == nil {
			t.Errorf("CheckPIN(%q): expected error", in)
		}
	}
}
