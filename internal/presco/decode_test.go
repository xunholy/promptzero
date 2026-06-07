// SPDX-License-Identifier: AGPL-3.0-or-later

package presco

import "testing"

func TestDecodeVectors(t *testing.T) {
	cases := []struct {
		hex  string
		full uint32
		site int
		user int
	}{
		{"10d00000000000000000000007aabbcc", 0x07AABBCC, 7, 48076},
		{"10d00000000000000000000000000001", 0x00000001, 0, 1},
		{"10d00000000000000000000012345678", 0x12345678, 18, 22136},
	}
	for _, c := range cases {
		r, err := Decode(c.hex)
		if err != nil {
			t.Fatalf("Decode(%s): %v", c.hex, err)
		}
		if r.FullCode != c.full {
			t.Errorf("%s: FullCode=0x%08X, want 0x%08X", c.hex, r.FullCode, c.full)
		}
		if r.SiteCode != c.site || r.UserCode != c.user {
			t.Errorf("%s: site=%d user=%d, want %d/%d", c.hex, r.SiteCode, r.UserCode, c.site, c.user)
		}
	}
}

func TestFullCodeHex(t *testing.T) {
	r, err := Decode("10d00000000000000000000007aabbcc")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.FullCodeHex != "07AABBCC" {
		t.Errorf("FullCodeHex=%q, want 07AABBCC", r.FullCodeHex)
	}
}

func TestStructuralRejection(t *testing.T) {
	// Wrong preamble.
	if _, err := Decode("10d00001000000000000000007aabbcc"); err == nil {
		t.Errorf("expected rejection of a frame with a bad preamble")
	}
	// Non-zero filler word (word 2).
	if _, err := Decode("10d00000000000010000000007aabbcc"); err == nil {
		t.Errorf("expected rejection of a frame with a non-zero filler word")
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz", "10d00000", "10d00000000000000000000007aabbcc00"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
