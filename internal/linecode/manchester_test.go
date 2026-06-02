// SPDX-License-Identifier: AGPL-3.0-or-later

package linecode

import "testing"

func candidate(r *ManchesterResult, align int) *ManchesterCandidate {
	for i := range r.Candidates {
		if r.Candidates[i].Alignment == align {
			return &r.Candidates[i]
		}
	}
	return nil
}

// TestDecodeManchester_RoundTrip: encode data IEEE-style, decode, recover it.
func TestDecodeManchester_RoundTrip(t *testing.T) {
	for _, data := range []string{"0", "1", "0110", "10101010", "11110000", "0"} {
		enc := EncodeManchesterIEEE(data)
		r, err := DecodeManchester(enc)
		if err != nil {
			t.Fatalf("%s: %v", data, err)
		}
		c := candidate(r, 0)
		if c == nil || !c.Valid {
			t.Fatalf("%s: alignment 0 should be valid, got %+v", data, c)
		}
		if c.IEEE8023 != data {
			t.Errorf("%s: IEEE decode = %s, want %s", data, c.IEEE8023, data)
		}
	}
}

// TestDecodeManchester_HandVector: 01101001 -> IEEE 0110, Thomas 1001.
func TestDecodeManchester_HandVector(t *testing.T) {
	r, err := DecodeManchester("01101001")
	if err != nil {
		t.Fatal(err)
	}
	c := candidate(r, 0)
	if c.IEEE8023 != "0110" {
		t.Errorf("IEEE = %s, want 0110", c.IEEE8023)
	}
	if c.Thomas != "1001" {
		t.Errorf("Thomas = %s, want 1001", c.Thomas)
	}
	if !c.Valid {
		t.Error("should be valid Manchester")
	}
}

// TestDecodeManchester_Invalid: 00/11 pairs are flagged.
func TestDecodeManchester_Invalid(t *testing.T) {
	r, err := DecodeManchester("0011")
	if err != nil {
		t.Fatal(err)
	}
	c := candidate(r, 0)
	if c.Valid {
		t.Error("00 11 pairs must be invalid")
	}
	if len(c.InvalidPairs) != 2 {
		t.Errorf("invalid pairs = %v, want 2", c.InvalidPairs)
	}
}

// TestDecodeManchester_Alignment: a stream with a leading half-bit decodes
// validly only at alignment 1.
func TestDecodeManchester_Alignment(t *testing.T) {
	// "01101001" is valid at align 0; prepend a '1' -> "101101001" (9 bits).
	r, err := DecodeManchester("101101001")
	if err != nil {
		t.Fatal(err)
	}
	a0, a1 := candidate(r, 0), candidate(r, 1)
	if a0.Valid {
		t.Error("alignment 0 should be invalid for the shifted stream")
	}
	if !a1.Valid || a1.IEEE8023 != "0110" {
		t.Errorf("alignment 1 should recover 0110, got %+v", a1)
	}
}

func TestDecodeManchester_Errors(t *testing.T) {
	for _, s := range []string{"", "012", "abc"} {
		if _, err := DecodeManchester(s); err == nil {
			t.Errorf("%q: expected error", s)
		}
	}
}
