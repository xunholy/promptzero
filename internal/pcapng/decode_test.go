package pcapng

import (
	"strings"
	"testing"
)

// hexToBytes strips whitespace from a test hex literal.
// We don't use the helper from stripSeparators in tests to
// keep the package boundary clean.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
}

func TestInspect_MinimalSHBOnly_LE(t *testing.T) {
	// SHB only, LE. Block Type 0x0A0D0D0A (palindrome) +
	// length 28 + BOM 0x1A2B3C4D (LE bytes 4D 3C 2B 1A) +
	// version 1.0 + section length -1 + trailing length 28.
	in := clean(`
		0A0D0D0A 1C000000
		4D3C2B1A 0100 0000
		FFFFFFFFFFFFFFFF
		1C000000`)
	b := decodeHex(t, in)
	s, err := Inspect(b, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if s.Endianness != "little" {
		t.Errorf("endianness: %q", s.Endianness)
	}
	if len(s.Sections) != 1 {
		t.Fatalf("sections: %d", len(s.Sections))
	}
	sec := s.Sections[0]
	if sec.MajorVersion != 1 || sec.MinorVersion != 0 {
		t.Errorf("version: %d.%d", sec.MajorVersion, sec.MinorVersion)
	}
	if sec.SectionLength != -1 {
		t.Errorf("section length: %d", sec.SectionLength)
	}
}

func TestInspect_MinimalSHBOnly_BE(t *testing.T) {
	in := clean(`
		0A0D0D0A 0000001C
		1A2B3C4D 0001 0000
		FFFFFFFFFFFFFFFF
		0000001C`)
	b := decodeHex(t, in)
	s, err := Inspect(b, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if s.Endianness != "big" {
		t.Errorf("endianness: %q", s.Endianness)
	}
}

func TestInspect_SHB_IDB_EPB_LE_Ethernet(t *testing.T) {
	in := clean(`
		0A0D0D0A 1C000000
		4D3C2B1A 01000000 FFFFFFFFFFFFFFFF
		1C000000
		01000000 14000000
		0100 0000 FFFF0000
		14000000
		06000000 24000000
		00000000 00000000 64000000 04000000 04000000
		DEADBEEF
		24000000`)
	b := decodeHex(t, in)
	s, err := Inspect(b, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(s.Sections) != 1 {
		t.Fatalf("sections: %d", len(s.Sections))
	}
	sec := s.Sections[0]
	if len(sec.Interfaces) != 1 {
		t.Fatalf("interfaces: %d", len(sec.Interfaces))
	}
	if sec.Interfaces[0].LinkType != 1 ||
		sec.Interfaces[0].LinkTypeName != "LINKTYPE_ETHERNET" {
		t.Errorf("interface link type: %+v", sec.Interfaces[0])
	}
	if sec.Interfaces[0].SnapLen != 65535 {
		t.Errorf("snaplen: %d", sec.Interfaces[0].SnapLen)
	}
	if len(sec.Records) != 1 {
		t.Fatalf("records: %d", len(sec.Records))
	}
	r := sec.Records[0]
	if r.CapturedLength != 4 || r.OriginalLength != 4 {
		t.Errorf("epb lengths: cap=%d orig=%d", r.CapturedLength, r.OriginalLength)
	}
	if r.PayloadHex != "DEADBEEF" {
		t.Errorf("payload hex: %q", r.PayloadHex)
	}
	if sec.BlockSummary["SHB"] != 1 || sec.BlockSummary["IDB"] != 1 ||
		sec.BlockSummary["EPB"] != 1 {
		t.Errorf("block summary: %+v", sec.BlockSummary)
	}
}

func TestInspect_SHBWithOptions_TextValues(t *testing.T) {
	// SHB with option 1 (comment) = "hello" + option 2
	// (shb_hardware) = "x86_64" + end-of-options.
	in := clean(`
		0A0D0D0A 38000000
		4D3C2B1A 01000000 FFFFFFFFFFFFFFFF
		0100 0500 68656C6C6F 000000
		0200 0600 7838365F3634 0000
		0000 0000
		38000000`)
	b := decodeHex(t, in)
	s, err := Inspect(b, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(s.Sections[0].Options) != 2 {
		t.Fatalf("options: %d", len(s.Sections[0].Options))
	}
	o := s.Sections[0].Options
	if o[0].ValueText != "hello" {
		t.Errorf("opt 1 text: %q", o[0].ValueText)
	}
	if o[1].ValueText != "x86_64" {
		t.Errorf("opt 2 text: %q", o[1].ValueText)
	}
}

func TestInspect_MultipleEPB_RecordsCap(t *testing.T) {
	// SHB + IDB + 3 EPBs. Cap MaxRecords=2.
	epb := func(tsLow string, payload string) string {
		// caplen = 4 (one 4-byte payload), block length = 36.
		return clean(`06000000 24000000 00000000 00000000 ` + tsLow + ` 04000000 04000000 ` + payload + ` 24000000`)
	}
	in := clean(`
		0A0D0D0A 1C000000
		4D3C2B1A 01000000 FFFFFFFFFFFFFFFF
		1C000000
		01000000 14000000
		0100 0000 FFFF0000
		14000000`) +
		epb("01000000", "11111111") +
		epb("02000000", "22222222") +
		epb("03000000", "33333333")
	b := decodeHex(t, in)
	s, err := Inspect(b, InspectOpts{MaxRecords: 2, MaxPayloadBytes: 4})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if s.Sections[0].BlockSummary["EPB"] != 3 {
		t.Errorf("EPB count: %d", s.Sections[0].BlockSummary["EPB"])
	}
	if len(s.Sections[0].Records) != 2 {
		t.Errorf("records returned: %d", len(s.Sections[0].Records))
	}
}

func TestInspect_TruncatedFile(t *testing.T) {
	_, err := Inspect([]byte{0x0A, 0x0D, 0x0D}, DefaultInspectOpts())
	if err == nil {
		t.Fatal("expected error on truncated file")
	}
}

func TestInspect_FirstBlockNotSHB(t *testing.T) {
	// 12 bytes of an IDB-shaped block (Type 1) is not allowed
	// as the first block.
	in := clean(`01000000 0C000000 0C000000`)
	b := decodeHex(t, in)
	_, err := Inspect(b, DefaultInspectOpts())
	if err == nil {
		t.Fatal("expected error when first block is not SHB")
	}
}

func TestInspect_BadByteOrderMagic_Note(t *testing.T) {
	// SHB header OK but BOM is wrong.
	in := clean(`
		0A0D0D0A 1C000000
		DEADBEEF 01000000 FFFFFFFFFFFFFFFF
		1C000000`)
	b := decodeHex(t, in)
	s, err := Inspect(b, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(s.Notes) == 0 {
		t.Fatal("expected a Note for bad BOM")
	}
	if !strings.Contains(s.Notes[0], "Byte-Order Magic") {
		t.Errorf("expected BOM note: %v", s.Notes)
	}
}

func TestInspect_BlockBackPointerMismatch_Note(t *testing.T) {
	// SHB with trailing length that doesn't match block
	// header length.
	in := clean(`
		0A0D0D0A 1C000000
		4D3C2B1A 01000000 FFFFFFFFFFFFFFFF
		DEADBEEF`)
	b := decodeHex(t, in)
	s, err := Inspect(b, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(s.Notes) == 0 {
		t.Fatal("expected a Note for back-pointer mismatch")
	}
	if !strings.Contains(s.Notes[0], "back-pointer") {
		t.Errorf("expected back-pointer note: %v", s.Notes)
	}
}

func TestInspect_TwoSections(t *testing.T) {
	// Two SHBs back-to-back, each minimal.
	in := clean(`
		0A0D0D0A 1C000000 4D3C2B1A 01000000 FFFFFFFFFFFFFFFF 1C000000
		0A0D0D0A 1C000000 4D3C2B1A 01000000 FFFFFFFFFFFFFFFF 1C000000`)
	b := decodeHex(t, in)
	s, err := Inspect(b, DefaultInspectOpts())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(s.Sections) != 2 {
		t.Errorf("sections: %d", len(s.Sections))
	}
}

// decodeHex turns a cleaned hex literal into bytes; fatal on
// invalid input.
func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, 0, len(s)/2)
	for i := 0; i+2 <= len(s); i += 2 {
		var n byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			switch {
			case c >= '0' && c <= '9':
				n = n*16 + (c - '0')
			case c >= 'a' && c <= 'f':
				n = n*16 + (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				n = n*16 + (c - 'A' + 10)
			default:
				t.Fatalf("bad hex char at %d: %q", i+j, c)
			}
		}
		b = append(b, n)
	}
	return b
}
