// SPDX-License-Identifier: AGPL-3.0-or-later

package isin

import "testing"

// realISINs are well-known, real International Securities Identification
// Numbers. Every assigned ISIN satisfies the ISO 6166 modulus-10 check,
// so they double as authoritative validation vectors: an incorrect
// algorithm could not make all five pass.
var realISINs = []struct {
	name, isin, prefix, nsin, check string
}{
	{"Apple", "US0378331005", "US", "037833100", "5"},
	{"IBM", "US4592001014", "US", "459200101", "4"},
	{"Nokia", "FI0009000681", "FI", "000900068", "1"},
	{"BAE Systems", "GB0002634946", "GB", "000263494", "6"},
	{"Microsoft", "US5949181045", "US", "594918104", "5"},
}

// TestDecode_RealISINs validates and field-splits each real ISIN.
func TestDecode_RealISINs(t *testing.T) {
	for _, c := range realISINs {
		t.Run(c.name, func(t *testing.T) {
			r, err := Decode(c.isin)
			if err != nil {
				t.Fatalf("Decode(%q) error: %v", c.isin, err)
			}
			if !r.LuhnValid {
				t.Errorf("Decode(%q) LuhnValid = false, want true", c.isin)
			}
			if r.Prefix != c.prefix {
				t.Errorf("Prefix = %q, want %q", r.Prefix, c.prefix)
			}
			if r.NSIN != c.nsin {
				t.Errorf("NSIN = %q, want %q", r.NSIN, c.nsin)
			}
			if r.CheckDigit != c.check {
				t.Errorf("CheckDigit = %q, want %q", r.CheckDigit, c.check)
			}
		})
	}
}

// TestDecode_SeparatorsAndCaseTolerated confirms grouped / lower-case
// pastes decode identically to the canonical form.
func TestDecode_SeparatorsAndCaseTolerated(t *testing.T) {
	for _, in := range []string{
		"US 0378 3310 05",
		"us0378331005",
		"US-0378-3310-05",
	} {
		r, err := Decode(in)
		if err != nil {
			t.Fatalf("Decode(%q) error: %v", in, err)
		}
		if r.ISIN != "US0378331005" || !r.LuhnValid {
			t.Errorf("Decode(%q) = %q valid=%v", in, r.ISIN, r.LuhnValid)
		}
	}
}

// TestDecode_BadChecksum is the verification-anchor behaviour: a mistyped
// ISIN fails Luhn but is still decoded (a soft note, not a hard error),
// and the expected check digit is recovered.
func TestDecode_BadChecksum(t *testing.T) {
	// Apple's ISIN with the check digit flipped 5 -> 4.
	r, err := Decode("US0378331004")
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if r.LuhnValid {
		t.Fatal("LuhnValid = true for a corrupted ISIN, want false")
	}
	if len(r.Notes) == 0 {
		t.Fatal("expected a note explaining the failed check, got none")
	}
}

// TestLuhnCheckDigit confirms the recovered check digit matches the real
// one for every valid ISIN (the recovery path used in notes).
func TestLuhnCheckDigit(t *testing.T) {
	for _, c := range realISINs {
		got := luhnCheckDigit(c.isin[:11])
		want := int(c.isin[11] - '0')
		if got != want {
			t.Errorf("luhnCheckDigit(%q) = %d, want %d", c.isin[:11], got, want)
		}
	}
}

// TestDecode_StructuralErrors covers the hard-error boundary cases.
func TestDecode_StructuralErrors(t *testing.T) {
	for _, in := range []string{
		"",              // empty
		"   ",           // only separators
		"US037833100",   // 11 chars (too short)
		"US03783310055", // 13 chars (too long)
		"US037833100$",  // invalid character
		"1S0378331005",  // prefix not 2 letters
		"US037833100A",  // check digit not numeric
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) = nil error, want structural error", in)
		}
	}
}

// FuzzDecode is a panic-safety guard: no byte string may crash the
// decoder, and any returned result must be self-consistent.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"US0378331005", "", "us 0378", "\x00\xff", "FI0009000681",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := Decode(s)
		if err != nil {
			return
		}
		if len(r.ISIN) != isinLength {
			t.Errorf("decoded ISIN has length %d, want %d", len(r.ISIN), isinLength)
		}
		if r.Prefix+r.NSIN+r.CheckDigit != r.ISIN {
			t.Errorf("fields do not reconstruct ISIN: %q + %q + %q != %q",
				r.Prefix, r.NSIN, r.CheckDigit, r.ISIN)
		}
	})
}
