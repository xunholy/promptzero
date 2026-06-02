// SPDX-License-Identifier: AGPL-3.0-or-later

package vin

import "testing"

// TestDecode_CanonicalCheckDigit uses the canonical ISO 3779 worked example
// (1M8GDM9AXKP042788), whose position-9 check digit is X.
func TestDecode_CanonicalCheckDigit(t *testing.T) {
	r, err := Decode("1M8GDM9AXKP042788")
	if err != nil {
		t.Fatal(err)
	}
	if r.CheckDigitComputed != "X" {
		t.Errorf("computed check digit = %s, want X", r.CheckDigitComputed)
	}
	if !r.CheckDigitValid {
		t.Error("check digit should be valid")
	}
	if r.WMI != "1M8" || r.Region != "North America" {
		t.Errorf("WMI/region = %s/%s, want 1M8/North America", r.WMI, r.Region)
	}
	if r.ModelYearCode != "K" {
		t.Errorf("model year code = %s, want K", r.ModelYearCode)
	}
	// K → index 9 in the cycle → 1989 / 2019.
	if len(r.ModelYearCandidates) != 2 || r.ModelYearCandidates[0] != 1989 || r.ModelYearCandidates[1] != 2019 {
		t.Errorf("model years = %v, want [1989 2019]", r.ModelYearCandidates)
	}
	if r.PlantCode != "P" || r.SerialSection != "042788" {
		t.Errorf("plant/serial = %s/%s, want P/042788", r.PlantCode, r.SerialSection)
	}
}

// TestDecode_AllOnes is a hand-computable vector: every character is '1', each
// transliterates to 1, so the weighted sum is the sum of the weights = 89,
// and 89 mod 11 = 1 — the position-9 character '1' matches.
func TestDecode_AllOnes(t *testing.T) {
	r, err := Decode("11111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if r.CheckDigitComputed != "1" || !r.CheckDigitValid {
		t.Errorf("computed/valid = %s/%v, want 1/true", r.CheckDigitComputed, r.CheckDigitValid)
	}
	// position-10 '1' → index 21 in the cycle → 2001 / 2031.
	if r.ModelYearCandidates[0] != 2001 {
		t.Errorf("model years = %v, want first 2001", r.ModelYearCandidates)
	}
}

// TestDecode_CheckDigitMismatch flips a non-check character so the check digit
// no longer matches — it must be reported invalid (advisory), not rejected.
func TestDecode_CheckDigitMismatch(t *testing.T) {
	// Last char 8 -> 9 changes the weighted sum; check digit X no longer holds.
	r, err := Decode("1M8GDM9AXKP042789")
	if err != nil {
		t.Fatal(err)
	}
	if r.CheckDigitValid {
		t.Error("check digit should be invalid after the edit")
	}
	if len(r.Notes) == 0 {
		t.Error("expected an advisory note on the mismatch")
	}
}

func TestDecode_Errors(t *testing.T) {
	bad := []string{
		"",                   // empty
		"1M8GDM9AXKP04278",   // 16 chars
		"1M8GDM9AXKP0427888", // 18 chars
		"1M8GDM9AXKP04278I",  // contains I (excluded)
		"1M8GDM9AXKP04278O",  // contains O (excluded)
		"1M8GDM9AXKP04278Q",  // contains Q (excluded)
		"1M8GDM9AXKP04278*",  // punctuation
	}
	for i, s := range bad {
		if _, err := Decode(s); err == nil {
			t.Errorf("case %d (%q): expected error", i, s)
		}
	}
}

// TestDecode_Region spot-checks the ISO 3780 first-character ranges.
func TestDecode_Region(t *testing.T) {
	cases := map[byte]string{
		'1': "North America", '5': "North America",
		'J': "Asia", 'R': "Asia",
		'S': "Europe", 'W': "Europe", 'Z': "Europe",
		'A': "Africa", 'H': "Africa",
		'6': "Oceania", '8': "South America",
	}
	for c, want := range cases {
		if got := region(c); got != want {
			t.Errorf("region(%c) = %s, want %s", c, got, want)
		}
	}
}
