// SPDX-License-Identifier: AGPL-3.0-or-later

package lei

import "testing"

// realLEIs are genuine GLEIF-registered Legal Entity Identifiers,
// confirmed live against the GLEIF API (api.gleif.org/api/v1/lei-records).
// Because every registered LEI satisfies ISO 17442 MOD-97-10, they double
// as authoritative validation vectors: an incorrect algorithm could not
// make all four pass (chance is 1/97 each).
var realLEIs = []struct {
	name, lei, lou, entity, check string
}{
	{"Apple", "HWUPKR0MPOU8FGXBT394", "HWUP", "KR0MPOU8FGXBT3", "94"},
	{"Deutsche Bank", "7LTWFZYICNSX8D621K86", "7LTW", "FZYICNSX8D621K", "86"},
	{"Microsoft", "INR2EJN1ERAN0W5ZP974", "INR2", "EJN1ERAN0W5ZP9", "74"},
	{"GLEIF Americas", "254900OPPU84GM83MG36", "2549", "00OPPU84GM83MG", "36"},
}

// TestDecode_RealLEIs validates and field-splits each real LEI.
func TestDecode_RealLEIs(t *testing.T) {
	for _, c := range realLEIs {
		t.Run(c.name, func(t *testing.T) {
			r, err := Decode(c.lei)
			if err != nil {
				t.Fatalf("Decode(%q) error: %v", c.lei, err)
			}
			if !r.Mod97Valid {
				t.Errorf("Decode(%q) Mod97Valid = false, want true", c.lei)
			}
			if r.LOUPrefix != c.lou {
				t.Errorf("LOUPrefix = %q, want %q", r.LOUPrefix, c.lou)
			}
			if r.EntityID != c.entity {
				t.Errorf("EntityID = %q, want %q", r.EntityID, c.entity)
			}
			if r.CheckDigits != c.check {
				t.Errorf("CheckDigits = %q, want %q", r.CheckDigits, c.check)
			}
		})
	}
}

// TestDecode_SeparatorsAndCaseTolerated confirms grouped / lower-case
// pastes decode identically to the canonical form.
func TestDecode_SeparatorsAndCaseTolerated(t *testing.T) {
	for _, in := range []string{
		"HWUP KR0M POU8 FGXB T394",
		"hwupkr0mpou8fgxbt394",
		"HWUP-KR0M-POU8-FGXB-T394",
	} {
		r, err := Decode(in)
		if err != nil {
			t.Fatalf("Decode(%q) error: %v", in, err)
		}
		if r.LEI != "HWUPKR0MPOU8FGXBT394" || !r.Mod97Valid {
			t.Errorf("Decode(%q) = %q valid=%v", in, r.LEI, r.Mod97Valid)
		}
	}
}

// TestDecode_BadChecksum is the verification-anchor behaviour: a mistyped
// LEI fails MOD-97-10 but is still decoded (a soft note, not a hard
// error), and the expected check digits are recovered.
func TestDecode_BadChecksum(t *testing.T) {
	// Apple's LEI with the last check digit flipped 4 -> 5.
	r, err := Decode("HWUPKR0MPOU8FGXBT395")
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if r.Mod97Valid {
		t.Fatal("Mod97Valid = true for a corrupted LEI, want false")
	}
	if len(r.Notes) == 0 {
		t.Fatal("expected a note explaining the failed check, got none")
	}
}

// TestExpectedCheckDigits confirms the recovered check digits match the
// real ones for every valid LEI (the recovery path used in notes).
func TestExpectedCheckDigits(t *testing.T) {
	for _, c := range realLEIs {
		got := expectedCheckDigits(c.lei)
		want := int(c.lei[18]-'0')*10 + int(c.lei[19]-'0')
		if got != want {
			t.Errorf("expectedCheckDigits(%q) = %02d, want %02d", c.lei, got, want)
		}
	}
}

// TestDecode_StructuralErrors covers the hard-error boundary cases.
func TestDecode_StructuralErrors(t *testing.T) {
	for _, in := range []string{
		"",                      // empty
		"   ",                   // only separators
		"HWUPKR0MPOU8FGXBT39",   // 19 chars (too short)
		"HWUPKR0MPOU8FGXBT3940", // 21 chars (too long)
		"HWUPKR0MPOU8FGXBT3$4",  // invalid character
		"HWUPKR0MPOU8FGXBT3A4",  // check digits not numeric
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
		"HWUPKR0MPOU8FGXBT394", "", "hwup kr0m", "\x00\xff",
		"254900OPPU84GM83MG36",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := Decode(s)
		if err != nil {
			return
		}
		if len(r.LEI) != leiLength {
			t.Errorf("decoded LEI has length %d, want %d", len(r.LEI), leiLength)
		}
		if r.LOUPrefix+r.EntityID+r.CheckDigits != r.LEI {
			t.Errorf("fields do not reconstruct LEI: %q + %q + %q != %q",
				r.LOUPrefix, r.EntityID, r.CheckDigits, r.LEI)
		}
	})
}
