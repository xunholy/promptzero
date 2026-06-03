// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

import "testing"

// Canonical GS1 EPC TDS worked example.
func TestDecode_SGTIN96_Canonical(t *testing.T) {
	r, err := DecodeHex("3074257BF7194E4000001A85")
	if err != nil {
		t.Fatal(err)
	}
	if r.Scheme != "SGTIN-96" || r.SchemeHeader != "0x30" {
		t.Fatalf("scheme = %s (%s)", r.Scheme, r.SchemeHeader)
	}
	s := r.SGTIN
	if s == nil {
		t.Fatal("SGTIN not decoded")
	}
	if s.Filter != 3 {
		t.Errorf("filter = %d, want 3", s.Filter)
	}
	if s.Partition != 5 {
		t.Errorf("partition = %d, want 5", s.Partition)
	}
	if s.CompanyPrefix != "0614141" {
		t.Errorf("company prefix = %q, want 0614141", s.CompanyPrefix)
	}
	if s.ItemReference != "812345" {
		t.Errorf("item reference = %q, want 812345", s.ItemReference)
	}
	if s.SerialNumber != 6789 {
		t.Errorf("serial = %d, want 6789", s.SerialNumber)
	}
	if s.TagURI != "urn:epc:tag:sgtin-96:3.0614141.812345.6789" {
		t.Errorf("tag URI = %q", s.TagURI)
	}
	if s.PureIdentityURI != "urn:epc:id:sgtin:0614141.812345.6789" {
		t.Errorf("pure identity URI = %q", s.PureIdentityURI)
	}
	// GTIN-14: indicator 8 + CP 0614141 + itemref-rest 12345 + check digit.
	if s.GTIN14 != "80614141123458" {
		t.Errorf("GTIN-14 = %q, want 80614141123458", s.GTIN14)
	}
}

// GS1 check-digit algorithm cross-check against known GTIN-13/14 check digits.
func TestGS1CheckDigit(t *testing.T) {
	// "629104150021" -> check digit 3 (GTIN-13 example 6291041500213).
	if got := gs1CheckDigit("629104150021"); got != 3 {
		t.Errorf("check digit = %d, want 3", got)
	}
	// "8061414112345" -> 8 (the canonical SGTIN example GTIN-14 base).
	if got := gs1CheckDigit("8061414112345"); got != 8 {
		t.Errorf("check digit = %d, want 8", got)
	}
}

func TestDecode_OtherSchemesIdentifiedNotDecoded(t *testing.T) {
	// SGLN-96 header 0x32 — recognised, not field-decoded.
	r, err := DecodeHex("320000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if r.Scheme != "SGLN-96" {
		t.Errorf("scheme = %s, want SGLN-96", r.Scheme)
	}
	if r.SGTIN != nil || r.SSCC != nil {
		t.Errorf("SGLN should not be field-decoded")
	}
	if len(r.Notes) == 0 {
		t.Errorf("deferred scheme should carry a note")
	}
}

func TestDecode_UnknownHeader(t *testing.T) {
	r, err := DecodeHex("FF0000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if r.Scheme != "unsupported" || len(r.Notes) == 0 {
		t.Errorf("unknown header handling: %+v", r)
	}
}

func TestDecode_Errors(t *testing.T) {
	if _, err := DecodeHex("3074"); err == nil {
		t.Error("non-12-byte EPC should error")
	}
	if _, err := DecodeHex(""); err == nil {
		t.Error("empty should error")
	}
	if _, err := DecodeHex("zzzz"); err == nil {
		t.Error("non-hex should error")
	}
}
