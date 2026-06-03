// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

import "testing"

// SGTIN-198 vectors from the epc-encoding-utils oracle (word-aligned 26-byte
// form). Same company prefix / item reference as the canonical SGTIN-96
// example, but with an alphanumeric serial.
func TestDecode_SGTIN198(t *testing.T) {
	cases := []struct {
		hex, serial, tagURI string
	}{
		{"3614257BF7194E60C286C5933000000000000000000000000000", "ABC123", "urn:epc:tag:sgtin-198:0.0614141.812345.ABC123"},
		{"3614257BF7194E6C59B4B5C80000000000000000000000000000", "XYZ-9", "urn:epc:tag:sgtin-198:0.0614141.812345.XYZ-9"},
	}
	for _, c := range cases {
		r, err := DecodeHex(c.hex)
		if err != nil {
			t.Fatalf("%s: %v", c.hex, err)
		}
		if r.Scheme != "SGTIN-198" || r.SGTIN == nil {
			t.Fatalf("%s: scheme=%s SGTIN=%v", c.hex, r.Scheme, r.SGTIN)
		}
		s := r.SGTIN
		if s.TagSize != 198 {
			t.Errorf("%s: tag size = %d, want 198", c.hex, s.TagSize)
		}
		if s.CompanyPrefix != "0614141" || s.ItemReference != "812345" {
			t.Errorf("%s: cp=%s ir=%s", c.hex, s.CompanyPrefix, s.ItemReference)
		}
		if s.SerialString != c.serial {
			t.Errorf("%s: serial = %q, want %q", c.hex, s.SerialString, c.serial)
		}
		if s.SerialNumber != 0 {
			t.Errorf("%s: numeric serial should be 0 for 198-bit, got %d", c.hex, s.SerialNumber)
		}
		if s.TagURI != c.tagURI {
			t.Errorf("%s: tag URI = %q, want %q", c.hex, s.TagURI, c.tagURI)
		}
		// GTIN-14 is shared with SGTIN-96 (same CP + item reference).
		if s.GTIN14 != "80614141123458" {
			t.Errorf("%s: GTIN-14 = %q, want 80614141123458", c.hex, s.GTIN14)
		}
		if s.PureIdentityURI != "urn:epc:id:sgtin:0614141.812345."+c.serial {
			t.Errorf("%s: pure URI = %q", c.hex, s.PureIdentityURI)
		}
	}
}

func TestDecode_198UnsupportedHeader(t *testing.T) {
	// 26-byte EPC with a non-SGTIN-198 header (GIAI-202 0x38) -> unsupported.
	r, err := DecodeHex("38" + "00000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if r.Scheme != "unsupported" || len(r.Notes) == 0 {
		t.Errorf("non-0x36 198-bit header should be unsupported: %+v", r)
	}
}

func TestDecode_LengthValidation(t *testing.T) {
	// 20 bytes is neither 12 nor 25/26 -> error.
	if _, err := DecodeHex("0011223344556677889900112233445566778899"); err == nil {
		t.Error("a 20-byte EPC should error")
	}
}
