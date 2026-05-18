package iso14443a

import (
	"strings"
	"testing"
)

// TestIdentify_MifareClassic1K pins the canonical Mifare
// Classic 1K identification — ATQA 0x0004, SAK 0x08, 4-byte
// UID starting with NXP manufacturer byte 0x04.
func TestIdentify_MifareClassic1K(t *testing.T) {
	got, err := Identify("0004", "08", "04 5A 3B FF", "")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.TagType != "Mifare Classic 1K" {
		t.Errorf("TagType = %q; want 'Mifare Classic 1K'", got.TagType)
	}
	if got.TagFamily != "Mifare Classic" {
		t.Errorf("TagFamily = %q", got.TagFamily)
	}
	if got.UIDInfo.LengthBytes != 4 {
		t.Errorf("UID length = %d; want 4", got.UIDInfo.LengthBytes)
	}
	if got.UIDInfo.ManufacturerName != "NXP Semiconductors" {
		t.Errorf("ManufacturerName = %q", got.UIDInfo.ManufacturerName)
	}
	if got.UIDInfo.CascadeTag {
		t.Error("4-byte UID with first byte 0x04 should not be cascade-tagged")
	}
	if got.SAK.ISO144434Compliant {
		t.Error("Classic 1K SAK 0x08 should not be ISO 14443-4 compliant")
	}
	if !got.SAK.ISO144433Only {
		t.Error("Classic 1K SAK 0x08 should be ISO 14443-3 only")
	}
}

// TestIdentify_MifareClassic4K pins Classic 4K.
func TestIdentify_MifareClassic4K(t *testing.T) {
	got, err := Identify("0002", "18", "04 5A 3B FF", "")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.TagType != "Mifare Classic 4K" {
		t.Errorf("TagType = %q; want 'Mifare Classic 4K'", got.TagType)
	}
}

// TestIdentify_MifareUltralight pins the Ultralight / NTAG
// family identification (ATQA 0x0044, SAK 0x00, 7-byte UID).
func TestIdentify_MifareUltralight(t *testing.T) {
	got, err := Identify("0044", "00", "04 65 8A B2 11 22 33", "")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.TagType != "Mifare Ultralight / NTAG" {
		t.Errorf("TagType = %q", got.TagType)
	}
	if got.UIDInfo.LengthBytes != 7 {
		t.Errorf("UID length = %d; want 7", got.UIDInfo.LengthBytes)
	}
	if got.ATQA.UIDSize != "double (7-byte)" {
		t.Errorf("ATQA.UIDSize = %q; want 'double (7-byte)'", got.ATQA.UIDSize)
	}
}

// TestIdentify_DESFire pins DESFire EV1/EV2/EV3 identification
// (ATQA 0x0344, SAK 0x20, 7-byte UID, ISO 14443-4 compliant).
func TestIdentify_DESFire(t *testing.T) {
	got, err := Identify("0344", "20", "04 65 8A B2 11 22 33", "")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.TagType != "Mifare DESFire EV1/EV2/EV3" {
		t.Errorf("TagType = %q", got.TagType)
	}
	if !got.SAK.ISO144434Compliant {
		t.Error("DESFire SAK 0x20 should be ISO 14443-4 compliant")
	}
	if got.SAK.ISO144433Only {
		t.Error("DESFire SAK 0x20 should NOT be ISO 14443-3 only")
	}
	if got.ATQA.Proprietary != 0x03 {
		t.Errorf("DESFire ATQA high byte should be 0x03; got 0x%02X", got.ATQA.Proprietary)
	}
}

// TestIdentify_DESFire_WithATS exercises the optional ATS
// decode path. DESFire EV1 typically returns:
//
//	TL=0x06 (6 bytes total), T0=0x75 (TA1+TB1+TC1 present,
//	  FSCI=5 → FSC=64), TA1=0x77, TB1=0x81, TC1=0x02 — total
//	  5 bytes after TL, but TL counts itself so that's 6 ✓
//
// NB: my earlier draft was missing a byte; the actual 6-byte
// DESFire ATS is TL + T0 + TA1 + TB1 + TC1 = 5 bytes, but TL
// counts itself, making the total length byte report 5 (not 6).
// So TL=05 is correct for 5 bytes total.
func TestIdentify_DESFire_WithATS(t *testing.T) {
	got, err := Identify("0344", "20", "04 65 8A B2 11 22 33", "05 75 77 81 02")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.ATS == nil {
		t.Fatal("ATS should be populated")
	}
	if got.ATS.LengthByte != 0x05 {
		t.Errorf("LengthByte = 0x%X; want 0x05", got.ATS.LengthByte)
	}
	if got.ATS.FSCI != 5 {
		t.Errorf("FSCI = %d; want 5", got.ATS.FSCI)
	}
	if got.ATS.FSC != 64 {
		t.Errorf("FSC = %d; want 64", got.ATS.FSC)
	}
	if !got.ATS.TA1Present || !got.ATS.TB1Present || !got.ATS.TC1Present {
		t.Errorf("TA1/TB1/TC1 presence wrong: TA1=%v TB1=%v TC1=%v",
			got.ATS.TA1Present, got.ATS.TB1Present, got.ATS.TC1Present)
	}
	if got.ATS.InterfaceBytesHex != "778102" {
		t.Errorf("InterfaceBytesHex = %q; want '778102'", got.ATS.InterfaceBytesHex)
	}
}

// TestIdentify_ATS_WithHistoricals — a card whose ATS carries
// historical bytes spelling "NF" with TC1 present.
//
// T0 bit layout per ISO 14443-4 §5.2.4:
//
//	bit 4 (0x10) = TA1 transmitted
//	bit 5 (0x20) = TB1 transmitted
//	bit 6 (0x40) = TC1 transmitted
//	bits 0-3     = FSCI
func TestIdentify_ATS_WithHistoricals(t *testing.T) {
	// TL=05 (5 bytes total), T0=0x40 (TC1 only, FSCI=0 → FSC=16),
	// TC1=0x02, then historicals = "NF" (2 bytes).
	got, err := Identify("0344", "20", "04 65 8A B2 11 22 33", "05 40 02 4E 46")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.ATS.HistoricalBytesHex != "4E46" {
		t.Errorf("HistoricalBytesHex = %q; want '4E46'", got.ATS.HistoricalBytesHex)
	}
	if got.ATS.HistoricalASCII != "NF" {
		t.Errorf("HistoricalASCII = %q; want 'NF'", got.ATS.HistoricalASCII)
	}
}

// TestIdentify_TripleUIDCascadeTag exercises a 10-byte UID
// starting with the 0x88 cascade tag.
func TestIdentify_TripleUIDCascadeTag(t *testing.T) {
	got, err := Identify("0044", "00", "88 01 02 03 04 05 06 07 08 09", "")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if !got.UIDInfo.CascadeTag {
		t.Error("UID starting with 0x88 should set CascadeTag")
	}
	// Manufacturer code after the cascade tag = byte 1 = 0x01.
	if got.UIDInfo.ManufacturerCode != 0x01 {
		t.Errorf("ManufacturerCode = 0x%02X; want 0x01 (after cascade tag)",
			got.UIDInfo.ManufacturerCode)
	}
	if got.UIDInfo.LengthBytes != 10 {
		t.Errorf("LengthBytes = %d; want 10", got.UIDInfo.LengthBytes)
	}
	if got.UIDInfo.LengthInvalid {
		t.Error("10-byte UID should not be flagged as length-invalid")
	}
}

// TestIdentify_UnknownCombination — an (ATQA, SAK) pair not in
// the table still returns a result; TagType = "Unknown" and
// TagFamily = "Other".
func TestIdentify_UnknownCombination(t *testing.T) {
	got, err := Identify("0001", "FF", "04 5A 3B FF", "")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.TagType != "Unknown" {
		t.Errorf("TagType = %q; want 'Unknown'", got.TagType)
	}
}

// TestIdentify_SAKOnlyFallback — when ATQA is unrecognised but
// SAK 0x20 indicates ISO 14443-4, the fallback table picks up.
func TestIdentify_SAKOnlyFallback(t *testing.T) {
	got, err := Identify("0001", "20", "04 5A 3B FF", "")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.TagType != "ISO 14443-4 compliant card" {
		t.Errorf("TagType = %q; want fallback ISO 14443-4", got.TagType)
	}
}

// TestParseATQA_EndianTolerance — the ATQA parser accepts
// either endian order ("0004" or "0400") and canonicalises to
// the form the public tables use.
func TestParseATQA_EndianTolerance(t *testing.T) {
	for _, in := range []string{"0004", "0400"} {
		got, err := Identify(in, "08", "04 5A 3B FF", "")
		if err != nil {
			t.Errorf("Identify(ATQA=%q): %v", in, err)
			continue
		}
		if got.TagType != "Mifare Classic 1K" {
			t.Errorf("Identify(ATQA=%q): TagType = %q; want 'Mifare Classic 1K'",
				in, got.TagType)
		}
	}
}

// TestIdentify_InvalidInput — input validation.
func TestIdentify_InvalidInput(t *testing.T) {
	if _, err := Identify("", "08", "04 5A 3B FF", ""); err == nil {
		t.Error("empty ATQA: want error")
	}
	if _, err := Identify("0004", "", "04 5A 3B FF", ""); err == nil {
		t.Error("empty SAK: want error")
	}
	if _, err := Identify("0004", "08", "", ""); err == nil {
		t.Error("empty UID: want error")
	}
	if _, err := Identify("00", "08", "04 5A 3B FF", ""); err == nil {
		t.Error("short ATQA: want error")
	}
	if _, err := Identify("0004", "0", "04 5A 3B FF", ""); err == nil {
		t.Error("short SAK: want error")
	}
	if _, err := Identify("ZZZZ", "08", "04 5A 3B FF", ""); err == nil {
		t.Error("invalid hex ATQA: want error")
	}
	if _, err := Identify("0004", "08", "04 5A 3B FF", "ZZ"); err == nil {
		t.Error("invalid hex ATS: want error")
	}
}

// TestIdentify_ToleratesSeparators — ':' / '-' / '_' / whitespace.
func TestIdentify_ToleratesSeparators(t *testing.T) {
	cases := []struct {
		atqa, sak, uid string
	}{
		{"00:04", "08", "04:5A:3B:FF"},
		{"00-04", "08", "04-5A-3B-FF"},
		{"00_04", "08", "04_5A_3B_FF"},
		{"  00 04 ", " 08 ", " 04 5A 3B FF "},
	}
	for _, c := range cases {
		got, err := Identify(c.atqa, c.sak, c.uid, "")
		if err != nil {
			t.Errorf("Identify(%q,%q,%q): %v", c.atqa, c.sak, c.uid, err)
			continue
		}
		if got.TagType != "Mifare Classic 1K" {
			t.Errorf("TagType = %q", got.TagType)
		}
	}
}

// TestIdentify_UIDLengthInvalid surfaces a flag when a UID is
// neither 4, 7, nor 10 bytes.
func TestIdentify_UIDLengthInvalid(t *testing.T) {
	got, err := Identify("0004", "08", "04 5A 3B FF AA BB CC DD EE", "")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if !got.UIDInfo.LengthInvalid {
		t.Errorf("9-byte UID should set LengthInvalid; got length=%d",
			got.UIDInfo.LengthBytes)
	}
}

// TestParseSAK_CompliantBits exercises the 14443-3 / 14443-4
// compliance bits explicitly.
func TestParseSAK_CompliantBits(t *testing.T) {
	cases := []struct {
		sak string
		v3  bool
		v4  bool
	}{
		{"08", true, false}, // Mifare Classic 1K (bit 5 clear)
		{"20", false, true}, // DESFire / 14443-4 (bit 5 set)
		{"28", false, true}, // JCOP / 14443-4 (bit 5 set)
		{"00", true, false}, // Ultralight (bit 5 clear)
		{"48", true, false}, // Proprietary bits 3+6, no 14443-4
	}
	for _, c := range cases {
		got, err := Identify("0004", c.sak, "04 5A 3B FF", "")
		if err != nil {
			t.Errorf("Identify(sak=%q): %v", c.sak, err)
			continue
		}
		if got.SAK.ISO144433Only != c.v3 {
			t.Errorf("SAK %s: ISO144433Only = %v; want %v", c.sak, got.SAK.ISO144433Only, c.v3)
		}
		if got.SAK.ISO144434Compliant != c.v4 {
			t.Errorf("SAK %s: ISO144434Compliant = %v; want %v",
				c.sak, got.SAK.ISO144434Compliant, c.v4)
		}
	}
}

// TestFSCITable spot-checks the FSCI → FSC mapping.
func TestFSCITable(t *testing.T) {
	cases := map[int]int{
		0: 16,
		1: 24,
		5: 64,
		8: 256,
	}
	for k, v := range cases {
		if got := fsciToFSC(k); got != v {
			t.Errorf("fsciToFSC(%d) = %d; want %d", k, got, v)
		}
	}
}

// TestATQA_Hex_ToleratesSeparators — separator strip in ATS too.
func TestParseATS_HistoricalBytesNotPrintable(t *testing.T) {
	// TL=04, T0=0x00 (no TA/TB/TC), 1 byte historical (0x10 — non-printable).
	got, err := Identify("0344", "20", "04 5A 3B FF AA BB CC", "04 00 10 11")
	if err != nil {
		t.Fatalf("Identify: %v", err)
	}
	if got.ATS == nil {
		t.Fatal("ATS missing")
	}
	if !strings.HasPrefix(got.ATS.HistoricalASCII, ".") {
		t.Errorf("HistoricalASCII = %q; want non-printable rendered as '.'",
			got.ATS.HistoricalASCII)
	}
}
