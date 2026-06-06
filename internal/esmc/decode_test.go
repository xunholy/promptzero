// SPDX-License-Identifier: AGPL-3.0-or-later

package esmc

import "testing"

// Vectors are built from scapy.contrib.esmc and hand-verified against
// ITU-T G.8264 (ESMC) + G.781 (SSM / QL).

func TestESMCInformationPRC(t *testing.T) {
	// subtype 0x0A, ITU OUI 0019A7, ituSubtype 1, version 1, event 0,
	// QL TLV ssmCode 0x02 (PRC under Option I).
	r, err := Decode("0a0019a700011000000001000402")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Subtype != 0x0A {
		t.Errorf("Subtype = 0x%02X", r.Subtype)
	}
	if r.ITUOUIHex != "0019A7" {
		t.Errorf("ITUOUIHex = %q", r.ITUOUIHex)
	}
	if r.ITUSubtype != 1 {
		t.Errorf("ITUSubtype = %d", r.ITUSubtype)
	}
	if r.Version != 1 {
		t.Errorf("Version = %d, want 1", r.Version)
	}
	if r.EventFlag {
		t.Error("EventFlag should be false (information frame)")
	}
	if len(r.TLVs) != 1 {
		t.Fatalf("got %d TLVs, want 1", len(r.TLVs))
	}
	tlv := r.TLVs[0]
	if tlv.Type != 1 || tlv.TypeName != "Quality Level" {
		t.Errorf("TLV type = %d/%q", tlv.Type, tlv.TypeName)
	}
	if tlv.QualityLevel != 2 {
		t.Errorf("QualityLevel = %d, want 2", tlv.QualityLevel)
	}
	if tlv.QualityLevelOptionI != "QL-PRC (G.811 primary reference clock)" {
		t.Errorf("OptionI = %q", tlv.QualityLevelOptionI)
	}
	// Option II for code 0x2 is unassigned.
	if tlv.QualityLevelOptionII != "reserved / unassigned (Option II)" {
		t.Errorf("OptionII = %q", tlv.QualityLevelOptionII)
	}
	if tlv.SSMCodeHex != "0x02" {
		t.Errorf("SSMCodeHex = %q", tlv.SSMCodeHex)
	}
}

func TestESMCEventDNU(t *testing.T) {
	// event=1, QL TLV ssmCode 0x0F (DNU under both options).
	r, err := Decode("0a0019a70001180000000100040f")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.EventFlag {
		t.Error("EventFlag should be true (event frame)")
	}
	if r.MessageType != "event (QL change — sent immediately)" {
		t.Errorf("MessageType = %q", r.MessageType)
	}
	tlv := r.TLVs[0]
	if tlv.QualityLevel != 0xF {
		t.Errorf("QualityLevel = %d, want 15", tlv.QualityLevel)
	}
	if tlv.QualityLevelOptionI != "QL-DNU (do not use for synchronisation)" {
		t.Errorf("OptionI = %q", tlv.QualityLevelOptionI)
	}
	if tlv.QualityLevelOptionII != "QL-DUS (do not use for synchronisation)" {
		t.Errorf("OptionII = %q", tlv.QualityLevelOptionII)
	}
}

func TestESMCRejectsNonESMCSubtype(t *testing.T) {
	// Slow-Protocol subtype 0x01 = LACP, not ESMC.
	if _, err := Decode("010019a7000110000000"); err == nil {
		t.Error("expected rejection of non-ESMC Slow-Protocol subtype")
	}
}

func TestESMCErrors(t *testing.T) {
	for _, in := range []string{"", "0a0019a7", "zz"} {
		// empty, 4 bytes (< 10), non-hex
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}

func TestESMCNoTLVs(t *testing.T) {
	// Valid 10-byte header, no TLVs — must not panic, empty TLV list.
	r, err := Decode("0a0019a70001100000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.TLVs) != 0 {
		t.Errorf("expected no TLVs, got %d", len(r.TLVs))
	}
}
