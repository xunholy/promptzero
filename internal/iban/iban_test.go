// SPDX-License-Identifier: AGPL-3.0-or-later

package iban

import (
	"strings"
	"testing"
)

// TestDecode_Valid runs the canonical example IBANs from the ISO 13616
// / SWIFT registry. Each must parse, split into the right fields, and
// pass the MOD-97-10 check.
func TestDecode_Valid(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		country string
		check   string
		bban    string
		length  int
	}{
		{"UK", "GB82WEST12345698765432", "GB", "82", "WEST12345698765432", 22},
		{"Germany", "DE89370400440532013000", "DE", "89", "370400440532013000", 22},
		{"France with letter in BBAN", "FR1420041010050500013M02606", "FR", "14", "20041010050500013M02606", 27},
		{"Norway shortest", "NO9386011117947", "NO", "93", "86011117947", 15},
		{"Belgium", "BE68539007547034", "BE", "68", "539007547034", 16},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := Decode(c.in)
			if err != nil {
				t.Fatalf("Decode(%q) error: %v", c.in, err)
			}
			if !r.Mod97Valid {
				t.Errorf("Decode(%q) Mod97Valid = false, want true", c.in)
			}
			if r.CountryCode != c.country {
				t.Errorf("CountryCode = %q, want %q", r.CountryCode, c.country)
			}
			if r.CheckDigits != c.check {
				t.Errorf("CheckDigits = %q, want %q", r.CheckDigits, c.check)
			}
			if r.BBAN != c.bban {
				t.Errorf("BBAN = %q, want %q", r.BBAN, c.bban)
			}
			if r.Length != c.length {
				t.Errorf("Length = %d, want %d", r.Length, c.length)
			}
		})
	}
}

// TestDecode_SeparatorsAndCaseTolerated confirms the print form (spaces)
// and a lower-case paste decode identically to the canonical form.
func TestDecode_SeparatorsAndCaseTolerated(t *testing.T) {
	want := "GB82WEST12345698765432"
	for _, in := range []string{
		"GB82 WEST 1234 5698 7654 32",
		"gb82west12345698765432",
		"GB82-WEST-1234-5698-7654-32",
	} {
		r, err := Decode(in)
		if err != nil {
			t.Fatalf("Decode(%q) error: %v", in, err)
		}
		if r.IBAN != want {
			t.Errorf("Decode(%q).IBAN = %q, want %q", in, r.IBAN, want)
		}
		if !r.Mod97Valid {
			t.Errorf("Decode(%q) Mod97Valid = false, want true", in)
		}
	}
}

// TestDecode_BadChecksum verifies the verification-anchor behaviour: a
// single mistyped digit fails MOD-97-10 but is still decoded (a soft
// note, not a hard error), and the expected check digits are recovered.
func TestDecode_BadChecksum(t *testing.T) {
	// Last digit of the valid UK example flipped 2 -> 1.
	r, err := Decode("GB82WEST12345698765431")
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if r.Mod97Valid {
		t.Fatal("Mod97Valid = true for a corrupted IBAN, want false")
	}
	if len(r.Notes) == 0 {
		t.Fatal("expected a note explaining the failed check, got none")
	}
}

// TestExpectedCheckDigits confirms the recomputed check digits match the
// real ones for every valid example (the recovery path used in notes).
func TestExpectedCheckDigits(t *testing.T) {
	for _, in := range []string{
		"GB82WEST12345698765432",
		"DE89370400440532013000",
		"FR1420041010050500013M02606",
		"NO9386011117947",
		"BE68539007547034",
	} {
		got := expectedCheckDigits(in)
		want := int(in[2]-'0')*10 + int(in[3]-'0')
		if got != want {
			t.Errorf("expectedCheckDigits(%q) = %02d, want %02d", in, got, want)
		}
	}
}

// TestGroup4 checks the print-form grouping, including a short final
// group.
func TestGroup4(t *testing.T) {
	if got := group4("GB82WEST12345698765432"); got != "GB82 WEST 1234 5698 7654 32" {
		t.Errorf("group4 = %q", got)
	}
}

// TestDecode_StructuralErrors covers the hard-error boundary cases that
// mean the input is not an IBAN at all.
func TestDecode_StructuralErrors(t *testing.T) {
	for _, in := range []string{
		"",                                     // empty
		"   ",                                  // only separators
		"GB82WEST1234",                         // too short
		"GB82WEST1234567890123456789012345678", // too long
		"GB82WEST1234$698765432",               // invalid character
		"1282WEST12345698765432",               // country code not letters
		"GBA2WEST12345698765432",               // check digits not digits
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) = nil error, want structural error", in)
		}
	}
}

// TestEncode_ReproducesCanonical confirms Encode computes the same check
// digits the canonical example IBANs carry (the inverse of Decode).
func TestEncode_ReproducesCanonical(t *testing.T) {
	cases := []struct{ country, bban, want string }{
		{"GB", "WEST12345698765432", "GB82WEST12345698765432"},
		{"DE", "370400440532013000", "DE89370400440532013000"},
		{"FR", "20041010050500013M02606", "FR1420041010050500013M02606"},
		{"NO", "86011117947", "NO9386011117947"},
		{"BE", "539007547034", "BE68539007547034"},
	}
	for _, c := range cases {
		r, err := Encode(c.country, c.bban)
		if err != nil {
			t.Fatalf("Encode(%q,%q) error: %v", c.country, c.bban, err)
		}
		if r.IBAN != c.want {
			t.Errorf("Encode(%q,%q).IBAN = %q, want %q", c.country, c.bban, r.IBAN, c.want)
		}
		if !r.Mod97Valid {
			t.Errorf("Encode(%q,%q) Mod97Valid = false, want true", c.country, c.bban)
		}
	}
}

// TestEncode_RoundTripsWithDecode is the inverse-pairing invariant:
// decoding a valid IBAN and re-encoding its parts reproduces it exactly.
func TestEncode_RoundTrips(t *testing.T) {
	for _, in := range []string{
		"GB82WEST12345698765432",
		"DE89370400440532013000",
		"FR1420041010050500013M02606",
		"NO9386011117947",
		"BE68539007547034",
	} {
		d, err := Decode(in)
		if err != nil {
			t.Fatalf("Decode(%q): %v", in, err)
		}
		e, err := Encode(d.CountryCode, d.BBAN)
		if err != nil {
			t.Fatalf("Encode round-trip of %q: %v", in, err)
		}
		if e.IBAN != in {
			t.Errorf("round-trip of %q = %q", in, e.IBAN)
		}
	}
}

// TestEncode_ToleratesSeparators confirms grouped / lower-case inputs
// encode to the same IBAN.
func TestEncode_ToleratesSeparators(t *testing.T) {
	r, err := Encode("gb", "west 1234 5698 7654 32")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if r.IBAN != "GB82WEST12345698765432" {
		t.Errorf("IBAN = %q", r.IBAN)
	}
}

// TestEncode_Errors covers the boundary rejections.
func TestEncode_Errors(t *testing.T) {
	cases := []struct{ country, bban string }{
		{"G", "WEST12345698765432"},     // country code too short
		{"G1", "WEST12345698765432"},    // country code not letters
		{"GB", "WEST$2345698765432"},    // invalid BBAN character
		{"GB", "12345"},                 // too short overall
		{"GB", strings.Repeat("1", 31)}, // too long overall
	}
	for _, c := range cases {
		if _, err := Encode(c.country, c.bban); err == nil {
			t.Errorf("Encode(%q,%q) = nil error, want error", c.country, c.bban)
		}
	}
}

// FuzzDecode is a panic-safety guard: no byte string may crash the
// decoder, and any returned result must be self-consistent.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"GB82WEST12345698765432", "DE89370400440532013000", "",
		"GB82 WEST 1234 5698 7654 32", "\x00\xff", "NO9386011117947",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := Decode(s)
		if err != nil {
			return
		}
		if r.Length != len(r.IBAN) {
			t.Errorf("Length %d != len(IBAN) %d", r.Length, len(r.IBAN))
		}
		if r.CountryCode+r.CheckDigits+r.BBAN != r.IBAN {
			t.Errorf("fields do not reconstruct IBAN: %q + %q + %q != %q",
				r.CountryCode, r.CheckDigits, r.BBAN, r.IBAN)
		}
	})
}
