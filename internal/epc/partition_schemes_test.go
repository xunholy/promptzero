// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

import "testing"

// All vectors below were produced by the epc-encoding-utils library used as an
// oracle, then asserted byte-for-byte here.

func TestDecode_GIAI96(t *testing.T) {
	cases := []struct {
		hex, cp string
		ref     uint64
		tagURI  string
	}{
		{"3414257BF400000000003039", "0614141", 12345, "urn:epc:tag:giai-96:0.0614141.12345"},
		{"341401388000000000000001", "0020000", 1, "urn:epc:tag:giai-96:0.0020000.1"},
		{"3400393243F1640000000063", "061414112345", 99, "urn:epc:tag:giai-96:0.061414112345.99"},
	}
	for _, c := range cases {
		r, err := DecodeHex(c.hex)
		if err != nil {
			t.Fatalf("%s: %v", c.hex, err)
		}
		if r.Scheme != "GIAI-96" || r.GIAI == nil {
			t.Fatalf("%s: scheme=%s GIAI=%v", c.hex, r.Scheme, r.GIAI)
		}
		if r.GIAI.CompanyPrefix != c.cp || r.GIAI.AssetReference != c.ref {
			t.Errorf("%s: got cp=%s ref=%d, want %s %d", c.hex, r.GIAI.CompanyPrefix, r.GIAI.AssetReference, c.cp, c.ref)
		}
		if r.GIAI.TagURI != c.tagURI {
			t.Errorf("%s: tag URI = %q, want %q", c.hex, r.GIAI.TagURI, c.tagURI)
		}
	}
}

func TestDecode_SGLN96(t *testing.T) {
	cases := []struct {
		hex, cp, loc string
		ext          uint64
		tagURI       string
	}{
		{"3214257BF460720000000190", "0614141", "12345", 400, "urn:epc:tag:sgln-96:0.0614141.12345.400"},
		{"3214257BF460720000000000", "0614141", "12345", 0, "urn:epc:tag:sgln-96:0.0614141.12345.0"},
	}
	for _, c := range cases {
		r, err := DecodeHex(c.hex)
		if err != nil {
			t.Fatalf("%s: %v", c.hex, err)
		}
		if r.Scheme != "SGLN-96" || r.SGLN == nil {
			t.Fatalf("%s: scheme=%s SGLN=%v", c.hex, r.Scheme, r.SGLN)
		}
		s := r.SGLN
		if s.CompanyPrefix != c.cp || s.LocationReference != c.loc || s.Extension != c.ext {
			t.Errorf("%s: got cp=%s loc=%s ext=%d, want %s %s %d", c.hex, s.CompanyPrefix, s.LocationReference, s.Extension, c.cp, c.loc, c.ext)
		}
		if s.TagURI != c.tagURI {
			t.Errorf("%s: tag URI = %q, want %q", c.hex, s.TagURI, c.tagURI)
		}
	}
}

func TestDecode_GRAI96(t *testing.T) {
	r, err := DecodeHex("3314257BF40C0E400000162E")
	if err != nil {
		t.Fatal(err)
	}
	if r.Scheme != "GRAI-96" || r.GRAI == nil {
		t.Fatalf("scheme=%s GRAI=%v", r.Scheme, r.GRAI)
	}
	g := r.GRAI
	if g.CompanyPrefix != "0614141" || g.AssetType != "12345" || g.SerialNumber != 5678 {
		t.Errorf("got cp=%s at=%s ser=%d, want 0614141 12345 5678", g.CompanyPrefix, g.AssetType, g.SerialNumber)
	}
	if g.TagURI != "urn:epc:tag:grai-96:0.0614141.12345.5678" {
		t.Errorf("tag URI = %q", g.TagURI)
	}
	if g.PureIdentityURI != "urn:epc:id:grai:0614141.12345.5678" {
		t.Errorf("pure identity URI = %q", g.PureIdentityURI)
	}
}
