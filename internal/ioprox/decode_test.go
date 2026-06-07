// SPDX-License-Identifier: AGPL-3.0-or-later

package ioprox

import "testing"

func TestDecodeHandTracedVector(t *testing.T) {
	// Hand-traced from the bit-layout spec (independent of this package's code):
	// FC=1, V=1, Card=1337 -> checksum 0xCF.
	r, err := Decode("007840603059cf3f")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.FacilityCode != 1 || r.Version != 1 || r.CardNumber != 1337 {
		t.Errorf("FC=%d V=%d card=%d, want 1/1/1337", r.FacilityCode, r.Version, r.CardNumber)
	}
	if !r.CRCValid || r.CRC != "0xCF" {
		t.Errorf("CRC=%s valid=%v, want 0xCF/true", r.CRC, r.CRCValid)
	}
	if r.XSF != "XSF(01)01:01337" {
		t.Errorf("XSF=%q, want XSF(01)01:01337", r.XSF)
	}
}

func TestDecodeMoreVectors(t *testing.T) {
	cases := []struct {
		hex           string
		fc, ver, card int
	}{
		{"007859605339ece3", 101, 2, 13117},
		{"00787fe07ffffc3f", 255, 3, 65535},
	}
	for _, c := range cases {
		r, err := Decode(c.hex)
		if err != nil {
			t.Fatalf("Decode(%s): %v", c.hex, err)
		}
		if r.FacilityCode != c.fc || r.Version != c.ver || r.CardNumber != c.card {
			t.Errorf("%s: FC=%d V=%d card=%d, want %d/%d/%d", c.hex, r.FacilityCode, r.Version, r.CardNumber, c.fc, c.ver, c.card)
		}
		if !r.CRCValid {
			t.Errorf("%s: CRC should be valid", c.hex)
		}
	}
}

func TestChecksumMismatchReported(t *testing.T) {
	// Take the valid FC=1/V=1/Card=1337 vector and flip one data bit (in the
	// card-high field) while leaving the checksum field and all separators
	// intact: the frame stays structurally an IO Prox block but the integrity
	// check must now fail and be reported (never asserted as a real credential).
	r, err := Decode("007840603079cf3f")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CRCValid {
		t.Errorf("expected CRC invalid after data mutation, got valid (crc=%s exp=%s)", r.CRC, r.CRCExpected)
	}
	if len(r.Notes) == 0 {
		t.Errorf("expected a mismatch note")
	}
}

func TestStructuralRejection(t *testing.T) {
	// Wrong marker (not 0xF0) must be rejected, not mis-decoded.
	if _, err := Decode("0011406030 59cf3f"); err == nil {
		t.Errorf("expected rejection of a frame with a bad marker")
	}
	// Non-zero preamble.
	if _, err := Decode("807840603059cf3f"); err == nil {
		t.Errorf("expected rejection of a frame with a non-zero preamble")
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz", "007840", "007840603059cf3f00"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
