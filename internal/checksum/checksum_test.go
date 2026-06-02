// SPDX-License-Identifier: AGPL-3.0-or-later

package checksum

import "testing"

// TestFletcherVectors is the verification gate for the Fletcher checksums:
// the published reference vectors (Wikipedia / RFC 1146) are the oracle.
func TestFletcherVectors(t *testing.T) {
	if got := fletcher16([]byte("abcdefgh")); got != 0x0627 {
		t.Errorf("Fletcher-16(abcdefgh) = 0x%04X, want 0x0627", got)
	}
	if got := fletcher32([]byte("abcde")); got != 0xF04FC729 {
		t.Errorf("Fletcher-32(abcde) = 0x%08X, want 0xF04FC729", got)
	}
}

// TestSimpleVectors hand-verifies sum/XOR/LRC on "123456789":
// byte sum = 477 (0x1DD) -> SUM-8 0xDD, SUM-16 0x01DD; XOR-8 0x31;
// Modbus LRC = two's complement of 0xDD = 0x23.
func TestSimpleVectors(t *testing.T) {
	d := []byte("123456789")
	cases := []struct {
		name string
		want uint32
	}{
		{"SUM-8", 0xDD},
		{"SUM-16", 0x01DD},
		{"XOR-8 (LRC)", 0x31},
		{"LRC-MODBUS", 0x23},
	}
	for _, c := range cases {
		a, ok := Lookup(c.name)
		if !ok {
			t.Fatalf("%s missing", c.name)
		}
		if got := a.Compute(d); got != c.want {
			t.Errorf("%s(123456789) = 0x%X, want 0x%X", c.name, got, c.want)
		}
	}
}

func TestIdentify(t *testing.T) {
	d := []byte("123456789")
	matches := Identify(d, 0x31) // XOR-8 = 0x31 (and SUM bytes won't equal 0x31)
	found := false
	for _, m := range matches {
		if m.Algo == "XOR-8 (LRC)" {
			found = true
		}
	}
	if !found {
		t.Errorf("Identify(0x31) should include XOR-8 (LRC); got %+v", matches)
	}
	// Fletcher identify round-trip.
	fl := fletcher16([]byte("abcdefgh"))
	got := Identify([]byte("abcdefgh"), fl)
	hit := false
	for _, m := range got {
		if m.Algo == "FLETCHER-16" {
			hit = true
		}
	}
	if !hit {
		t.Errorf("Identify did not match FLETCHER-16; got %+v", got)
	}
}

func TestFormat(t *testing.T) {
	a8, _ := Lookup("SUM-8")
	if a8.Format(0xDD) != "0xDD" {
		t.Errorf("SUM-8 format = %s, want 0xDD", a8.Format(0xDD))
	}
	a32, _ := Lookup("FLETCHER-32")
	if a32.Format(0xF04FC729) != "0xF04FC729" {
		t.Errorf("FLETCHER-32 format = %s, want 0xF04FC729", a32.Format(0xF04FC729))
	}
}
