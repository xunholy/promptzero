// SPDX-License-Identifier: AGPL-3.0-or-later

package aba

import "testing"

// realRTNs are real, well-known US bank routing numbers. Every assigned
// RTN satisfies the ABA weighted modulus-10 checksum, so they double as
// authoritative validation vectors: an incorrect algorithm could not
// make all of them pass.
var realRTNs = []struct {
	name, rtn string
	district  int
	dName     string
}{
	{"JPMorgan Chase NY", "021000021", 2, "New York"},
	{"FRB Boston (FedACH)", "011000015", 1, "Boston"},
	{"Bank of America CA", "121000358", 12, "San Francisco"},
	{"Bank of America NY", "026009593", 2, "New York"},
	{"Chase IL", "071000013", 7, "Chicago"},
}

// TestDecode_RealRTNs validates and field-splits each real routing number.
func TestDecode_RealRTNs(t *testing.T) {
	for _, c := range realRTNs {
		t.Run(c.name, func(t *testing.T) {
			r, err := Decode(c.rtn)
			if err != nil {
				t.Fatalf("Decode(%q) error: %v", c.rtn, err)
			}
			if !r.ChecksumValid {
				t.Errorf("Decode(%q) ChecksumValid = false, want true", c.rtn)
			}
			if r.District != c.district {
				t.Errorf("District = %d, want %d", r.District, c.district)
			}
			if r.DistrictName != c.dName {
				t.Errorf("DistrictName = %q, want %q", r.DistrictName, c.dName)
			}
			if r.RoutingSymbol != c.rtn[:4] || r.InstitutionID != c.rtn[4:8] || r.CheckDigit != c.rtn[8:9] {
				t.Errorf("field split wrong: %+v", r)
			}
		})
	}
}

// TestDecode_Thrift covers the 21-32 thrift prefix range (district =
// prefix - 20).
func TestDecode_Thrift(t *testing.T) {
	// 322271627 (a Chase CA thrift-range RTN): prefix 32 → district 12.
	r, err := Decode("322271627")
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if !r.ChecksumValid {
		t.Error("ChecksumValid = false, want true")
	}
	if r.Type != "Thrift institution" || r.District != 12 || r.DistrictName != "San Francisco" {
		t.Errorf("got type=%q district=%d name=%q", r.Type, r.District, r.DistrictName)
	}
}

// TestDecode_SeparatorsTolerated confirms grouped pastes (MICR / form
// formatting) decode identically.
func TestDecode_SeparatorsTolerated(t *testing.T) {
	for _, in := range []string{"0210 0002 1", "021-000-021", "021:000:021"} {
		r, err := Decode(in)
		if err != nil {
			t.Fatalf("Decode(%q) error: %v", in, err)
		}
		if r.RoutingNumber != "021000021" || !r.ChecksumValid {
			t.Errorf("Decode(%q) = %q valid=%v", in, r.RoutingNumber, r.ChecksumValid)
		}
	}
}

// TestDecode_BadChecksum is the verification-anchor behaviour: a
// transposed RTN fails the checksum but is still decoded (a soft note,
// not a hard error).
func TestDecode_BadChecksum(t *testing.T) {
	// JPMorgan RTN with the check digit bumped 1 -> 2.
	r, err := Decode("021000022")
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if r.ChecksumValid {
		t.Fatal("ChecksumValid = true for a corrupted RTN, want false")
	}
	if len(r.Notes) == 0 {
		t.Fatal("expected a note explaining the failed checksum, got none")
	}
}

// TestDecode_StructuralErrors covers the hard-error boundary cases.
func TestDecode_StructuralErrors(t *testing.T) {
	for _, in := range []string{
		"",           // empty
		"   ",        // only separators
		"02100002",   // 8 digits (too short)
		"0210000211", // 10 digits (too long)
		"02100002A",  // contains a letter
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) = nil error, want structural error", in)
		}
	}
}

// FuzzDecode is a panic-safety guard: no byte string may crash the
// decoder, and any returned result must be self-consistent.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"021000021", "", "0210 0002 1", "\x00\xff", "999999999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := Decode(s)
		if err != nil {
			return
		}
		if len(r.RoutingNumber) != rtnLength {
			t.Errorf("decoded RTN length %d, want %d", len(r.RoutingNumber), rtnLength)
		}
		if r.RoutingSymbol+r.InstitutionID+r.CheckDigit != r.RoutingNumber {
			t.Errorf("fields do not reconstruct RTN: %q+%q+%q != %q",
				r.RoutingSymbol, r.InstitutionID, r.CheckDigit, r.RoutingNumber)
		}
	})
}
