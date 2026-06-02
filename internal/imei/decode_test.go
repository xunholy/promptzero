// SPDX-License-Identifier: AGPL-3.0-or-later

package imei

import "testing"

// TestDecode_GSMAExample uses the canonical GSMA example IMEI 490154203237518,
// whose Luhn check digit is 8.
func TestDecode_GSMAExample(t *testing.T) {
	r, err := Decode("490154203237518")
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != "IMEI" {
		t.Errorf("type = %s, want IMEI", r.Type)
	}
	if r.TAC != "49015420" || r.SerialNumber != "323751" || r.CheckDigit != "8" {
		t.Errorf("TAC/SNR/check = %s/%s/%s, want 49015420/323751/8", r.TAC, r.SerialNumber, r.CheckDigit)
	}
	if r.ReportingBodyID != "49" {
		t.Errorf("RBI = %s, want 49", r.ReportingBodyID)
	}
	if r.CheckDigitComputed != "8" || !r.LuhnValid {
		t.Errorf("computed/valid = %s/%v, want 8/true", r.CheckDigitComputed, r.LuhnValid)
	}
}

// TestDecode_SeparatorsTolerated checks the GSMA example with the common
// dashed grouping (TAC-SNR-CD) still decodes.
func TestDecode_SeparatorsTolerated(t *testing.T) {
	r, err := Decode("49-015420-323751-8")
	if err != nil {
		t.Fatal(err)
	}
	if !r.LuhnValid || r.Number != "490154203237518" {
		t.Errorf("dashed IMEI = %+v", r)
	}
}

func TestDecode_LuhnFail(t *testing.T) {
	// Flip the check digit 8 -> 7.
	r, err := Decode("490154203237517")
	if err != nil {
		t.Fatal(err)
	}
	if r.LuhnValid {
		t.Error("check digit 7 should fail Luhn")
	}
	if r.CheckDigitComputed != "8" {
		t.Errorf("computed = %s, want 8", r.CheckDigitComputed)
	}
	if len(r.Notes) == 0 {
		t.Error("expected a mismatch note")
	}
}

func TestDecode_IMEISV(t *testing.T) {
	// 16 digits: TAC + SNR + 2-digit software version, no Luhn check.
	r, err := Decode("4901542032375103")
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != "IMEISV" {
		t.Errorf("type = %s, want IMEISV", r.Type)
	}
	if r.TAC != "49015420" || r.SerialNumber != "323751" || r.SoftwareVersion != "03" {
		t.Errorf("TAC/SNR/SVN = %s/%s/%s, want 49015420/323751/03", r.TAC, r.SerialNumber, r.SoftwareVersion)
	}
	if r.LuhnValid {
		t.Error("IMEISV must not be marked Luhn-valid")
	}
}

func TestDecode_Errors(t *testing.T) {
	bad := []string{
		"",                  // empty
		"49015420323751",    // 14 digits
		"49015420323751812", // 17 digits
		"49015420A237518",   // non-digit
	}
	for i, s := range bad {
		if _, err := Decode(s); err == nil {
			t.Errorf("case %d (%q): expected error", i, s)
		}
	}
}

// TestLuhnCheckDigit hand-verifies the algorithm against the GSMA payload.
func TestLuhnCheckDigit(t *testing.T) {
	if got := luhnCheckDigit("49015420323751"); got != 8 {
		t.Errorf("luhnCheckDigit(49015420323751) = %d, want 8", got)
	}
}
