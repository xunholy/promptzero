// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

import (
	"strings"
	"testing"
)

// Extended-scheme vectors (GRAI-170 / GIAI-202 / SGLN-195) generated and
// verified byte-for-byte against the epc-tds library used as an oracle, in the
// word-aligned form a RAIN reader emits. Each carries an alphanumeric trailing
// field (serial / asset reference / extension) that the 96-bit sibling cannot.
func TestDecode_GRAI170(t *testing.T) {
	cases := []struct {
		hex, cp, at, serial, tag, id string
	}{
		{
			"371A57BF400C0E60C286B58800000000000000000000",
			"614141", "012345", "ABC-1",
			"urn:epc:tag:grai-170:0.614141.012345.ABC-1",
			"urn:epc:id:grai:614141.012345.ABC-1",
		},
		{ // partition 5, filter 3, punctuation in the serial
			"3774F4E4E40010E9E5E5A70EC46E4000000000000000",
			"4012345", "00067", "Serial#9",
			"urn:epc:tag:grai-170:3.4012345.00067.Serial#9",
			"urn:epc:id:grai:4012345.00067.Serial#9",
		},
	}
	for _, c := range cases {
		r, err := DecodeHex(c.hex)
		if err != nil {
			t.Fatalf("%s: %v", c.hex, err)
		}
		if r.Scheme != "GRAI-170" || r.GRAI == nil {
			t.Fatalf("%s: scheme=%s GRAI=%v", c.hex, r.Scheme, r.GRAI)
		}
		g := r.GRAI
		if g.TagSize != 170 {
			t.Errorf("%s: tag size = %d, want 170", c.hex, g.TagSize)
		}
		if g.CompanyPrefix != c.cp || g.AssetType != c.at {
			t.Errorf("%s: cp=%s at=%s, want %s/%s", c.hex, g.CompanyPrefix, g.AssetType, c.cp, c.at)
		}
		if g.SerialString != c.serial {
			t.Errorf("%s: serial = %q, want %q", c.hex, g.SerialString, c.serial)
		}
		if g.SerialNumber != 0 {
			t.Errorf("%s: numeric serial should be 0 for 170-bit, got %d", c.hex, g.SerialNumber)
		}
		if g.TagURI != c.tag {
			t.Errorf("%s: tag URI = %q, want %q", c.hex, g.TagURI, c.tag)
		}
		if g.PureIdentityURI != c.id {
			t.Errorf("%s: id URI = %q, want %q", c.hex, g.PureIdentityURI, c.id)
		}
	}
}

func TestDecode_GIAI202(t *testing.T) {
	cases := []struct {
		hex, cp, ref, tag, id string
	}{
		{
			"381A57BF6C59B4DDC39000000000000000000000000000000000",
			"614141", "XYZ789",
			"urn:epc:tag:giai-202:0.614141.XYZ789",
			"urn:epc:id:giai:614141.XYZ789",
		},
		{ // partition 5 -> a narrower company prefix, wider asset-reference field
			"38B4F4E4E60D3A716A2D60C18800000000000000000000000000",
			"4012345", "ASSET-001",
			"urn:epc:tag:giai-202:5.4012345.ASSET-001",
			"urn:epc:id:giai:4012345.ASSET-001",
		},
	}
	for _, c := range cases {
		r, err := DecodeHex(c.hex)
		if err != nil {
			t.Fatalf("%s: %v", c.hex, err)
		}
		if r.Scheme != "GIAI-202" || r.GIAI == nil {
			t.Fatalf("%s: scheme=%s GIAI=%v", c.hex, r.Scheme, r.GIAI)
		}
		g := r.GIAI
		if g.TagSize != 202 {
			t.Errorf("%s: tag size = %d, want 202", c.hex, g.TagSize)
		}
		if g.CompanyPrefix != c.cp {
			t.Errorf("%s: cp=%s, want %s", c.hex, g.CompanyPrefix, c.cp)
		}
		if g.AssetReferenceString != c.ref {
			t.Errorf("%s: asset ref = %q, want %q", c.hex, g.AssetReferenceString, c.ref)
		}
		if g.AssetReference != 0 {
			t.Errorf("%s: numeric asset ref should be 0 for 202-bit, got %d", c.hex, g.AssetReference)
		}
		if g.TagURI != c.tag || g.PureIdentityURI != c.id {
			t.Errorf("%s: URIs = %q / %q, want %q / %q", c.hex, g.TagURI, g.PureIdentityURI, c.tag, c.id)
		}
	}
}

func TestDecode_SGLN195(t *testing.T) {
	cases := []struct {
		hex, cp, loc, ext, tag, id string
	}{
		{
			"391A57BF40607316C545AD1900000000000000000000000000",
			"614141", "012345", "EXT-42",
			"urn:epc:tag:sgln-195:0.614141.012345.EXT-42",
			"urn:epc:id:sgln:614141.012345.EXT-42",
		},
		{ // partition 2, filter 2, dotted extension
			"394DFC24F0F055937EFE4B9B80000000000000000000000000",
			"532827919", "042", "door.7",
			"urn:epc:tag:sgln-195:2.532827919.042.door.7",
			"urn:epc:id:sgln:532827919.042.door.7",
		},
		{ // single-character extension (minimum length)
			"391A57BF406073140000000000000000000000000000000000",
			"614141", "012345", "E",
			"urn:epc:tag:sgln-195:0.614141.012345.E",
			"urn:epc:id:sgln:614141.012345.E",
		},
	}
	for _, c := range cases {
		r, err := DecodeHex(c.hex)
		if err != nil {
			t.Fatalf("%s: %v", c.hex, err)
		}
		if r.Scheme != "SGLN-195" || r.SGLN == nil {
			t.Fatalf("%s: scheme=%s SGLN=%v", c.hex, r.Scheme, r.SGLN)
		}
		s := r.SGLN
		if s.TagSize != 195 {
			t.Errorf("%s: tag size = %d, want 195", c.hex, s.TagSize)
		}
		if s.CompanyPrefix != c.cp || s.LocationReference != c.loc {
			t.Errorf("%s: cp=%s loc=%s, want %s/%s", c.hex, s.CompanyPrefix, s.LocationReference, c.cp, c.loc)
		}
		if s.ExtensionString != c.ext {
			t.Errorf("%s: extension = %q, want %q", c.hex, s.ExtensionString, c.ext)
		}
		if s.TagURI != c.tag || s.PureIdentityURI != c.id {
			t.Errorf("%s: URIs = %q / %q, want %q / %q", c.hex, s.TagURI, s.PureIdentityURI, c.tag, c.id)
		}
	}
}

// GIAI-202's individual asset reference is the alphanumeric remainder of the
// 202-bit tag, so its field width (202 − 14 − companyPrefixBits) is the only
// part of the extended-scheme decode that varies with the partition — the one
// place a width miscalculation could confidently mis-decode. Sweep every
// partition 0-6 (widest company prefix / narrowest reference through narrowest
// prefix / widest reference) against the epc-tds oracle. Vectors carry the
// partition index inside the reference ("R<p>xZ") so a cross-partition mixup
// can't pass.
func TestDecode_GIAI202AllPartitions(t *testing.T) {
	cases := map[string]string{
		"382072FA646852930F1680000000000000000000000000000000": "urn:epc:tag:giai-202:1.123456789012.R0xZ",
		"38245BFB8386B498F8B400000000000000000000000000000000": "urn:epc:tag:giai-202:1.12345678901.R1xZ",
		"3828499602D2A4CBC5A000000000000000000000000000000000": "urn:epc:tag:giai-202:1.1234567890.R2xZ",
		"382C75BCD15A4CFC5A0000000000000000000000000000000000": "urn:epc:tag:giai-202:1.123456789.R3xZ",
		"38305E30A75269E2D00000000000000000000000000000000000": "urn:epc:tag:giai-202:1.12345678.R4xZ",
		"38344B5A1E935F16800000000000000000000000000000000000": "urn:epc:tag:giai-202:1.1234567.R5xZ",
		"383878902936F168000000000000000000000000000000000000": "urn:epc:tag:giai-202:1.123456.R6xZ",
	}
	for hx, want := range cases {
		r, err := DecodeHex(hx)
		if err != nil {
			t.Fatalf("%s: %v", hx, err)
		}
		if r.GIAI == nil {
			t.Fatalf("%s: GIAI nil (scheme=%s)", hx, r.Scheme)
		}
		if r.GIAI.TagURI != want {
			t.Errorf("%s:\n got %q\nwant %q", hx, r.GIAI.TagURI, want)
		}
	}
}

// At partition 0 the GRAI asset-type and SGLN location-reference fields have
// zero digits. The decoder renders them EMPTY — matching the shipped 96-bit
// siblings (GRAI-96 / SGLN-96), which is a deliberate divergence from epc-tds
// (it renders a lone "0"). Lock the convention so a future maintainer
// re-verifying against epc-tds doesn't "fix" it into an inconsistency.
func TestDecode_ExtendedPartition0EmptyField(t *testing.T) {
	// GRAI-170 p0: urn:epc:tag:grai-170:0.123456789012.<empty>.Z9
	if r, _ := DecodeHex("370072FA6468502D3900000000000000000000000000"); r.GRAI == nil || r.GRAI.AssetType != "" {
		t.Errorf("GRAI-170 p0 asset type = %q, want empty (GRAI-96 convention)", grAssetType(r))
	}
	// SGLN-195 p0: urn:epc:tag:sgln-195:0.123456789012.<empty>.Q1
	if r, _ := DecodeHex("390072FA646851458800000000000000000000000000000000"); r.SGLN == nil || r.SGLN.LocationReference != "" {
		t.Errorf("SGLN-195 p0 location = %q, want empty (SGLN-96 convention)", sgLoc(r))
	}
}

func grAssetType(r *Result) string {
	if r.GRAI == nil {
		return "<nil>"
	}
	return r.GRAI.AssetType
}

func sgLoc(r *Result) string {
	if r.SGLN == nil {
		return "<nil>"
	}
	return r.SGLN.LocationReference
}

// A recognised extended header supplied with too few bits must be reported as a
// truncated tag, not silently zero-extended into a wrong asset reference.
func TestDecode_ExtendedTruncated(t *testing.T) {
	// GIAI-202 (0x38) needs 202 bits, but a 22-byte word is only 176.
	r, err := DecodeHex("38" + strings.Repeat("0", 42)) // 22 bytes
	if err != nil {
		t.Fatal(err)
	}
	if r.Scheme != "unsupported" || len(r.Notes) == 0 {
		t.Errorf("truncated GIAI-202 should be unsupported with a note: %+v", r)
	}
}

// An unrecognised extended header (GDTI-174, 0x3E) is reported unsupported
// rather than guessed.
func TestDecode_ExtendedUnsupportedHeader(t *testing.T) {
	r, err := DecodeHex("3E" + strings.Repeat("0", 42)) // 22 bytes
	if err != nil {
		t.Fatal(err)
	}
	if r.Scheme != "unsupported" || len(r.Notes) == 0 {
		t.Errorf("GDTI-174 header should be unsupported: %+v", r)
	}
}

// The 96-bit siblings still decode and now report their tag size.
func TestDecode_96TagSizeStamped(t *testing.T) {
	for _, hx := range []string{
		"3314257BF40C0E400000162E", // GRAI-96
		"3214257BF460720000000190", // SGLN-96
		"3414257BF400000000003039", // GIAI-96
	} {
		r, err := DecodeHex(hx)
		if err != nil {
			t.Fatalf("%s: %v", hx, err)
		}
		switch {
		case r.GRAI != nil && r.GRAI.TagSize != 96:
			t.Errorf("%s: GRAI tag size = %d, want 96", hx, r.GRAI.TagSize)
		case r.SGLN != nil && r.SGLN.TagSize != 96:
			t.Errorf("%s: SGLN tag size = %d, want 96", hx, r.SGLN.TagSize)
		case r.GIAI != nil && r.GIAI.TagSize != 96:
			t.Errorf("%s: GIAI tag size = %d, want 96", hx, r.GIAI.TagSize)
		}
	}
}
