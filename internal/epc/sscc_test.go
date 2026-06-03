// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

import "testing"

// Worked SSCC-96 example (erfideo EPC converter):
// 3134257BF4499602D2000000 -> urn:epc:tag:sscc-96:1.0614141.1234567890
func TestDecode_SSCC96_Canonical(t *testing.T) {
	r, err := DecodeHex("3134257BF4499602D2000000")
	if err != nil {
		t.Fatal(err)
	}
	if r.Scheme != "SSCC-96" || r.SchemeHeader != "0x31" {
		t.Fatalf("scheme = %s (%s)", r.Scheme, r.SchemeHeader)
	}
	s := r.SSCC
	if s == nil {
		t.Fatal("SSCC not decoded")
	}
	if s.Filter != 1 {
		t.Errorf("filter = %d, want 1", s.Filter)
	}
	if s.Partition != 5 {
		t.Errorf("partition = %d, want 5", s.Partition)
	}
	if s.CompanyPrefix != "0614141" {
		t.Errorf("company prefix = %q, want 0614141", s.CompanyPrefix)
	}
	if s.SerialReference != "1234567890" {
		t.Errorf("serial reference = %q, want 1234567890", s.SerialReference)
	}
	if s.TagURI != "urn:epc:tag:sscc-96:1.0614141.1234567890" {
		t.Errorf("tag URI = %q", s.TagURI)
	}
	if s.PureIdentityURI != "urn:epc:id:sscc:0614141.1234567890" {
		t.Errorf("pure identity URI = %q", s.PureIdentityURI)
	}
	// SSCC-18: extension 1 + CP 0614141 + serialref-rest 234567890 + check.
	if s.SSCC18 != "106141412345678908" {
		t.Errorf("SSCC-18 = %q, want 106141412345678908", s.SSCC18)
	}
}

func TestSSCC18_CheckDigit(t *testing.T) {
	// base17 "10614141234567890" -> check digit 8 (verified independently).
	if got := gs1CheckDigit("10614141234567890"); got != 8 {
		t.Errorf("check digit = %d, want 8", got)
	}
}
