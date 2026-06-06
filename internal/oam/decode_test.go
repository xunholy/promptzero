// SPDX-License-Identifier: AGPL-3.0-or-later

package oam

import "testing"

// Vectors produced with scapy's OAM layer (scapy.contrib.oam) and verified
// field-for-field.

func TestDecodeCCM(t *testing.T) {
	// OAM(mel=5, opcode=1, flags RDI set, period=4, seq=0xdeadbeef,
	//   mep_id=8191, meg_id="\x20\x06ICC-MEG-0001"+pad)
	const v = "a0018446deadbeef1fff20064943432d4d45472d30303031000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MDLevel != 5 {
		t.Errorf("md level = %d, want 5", r.MDLevel)
	}
	if r.OpcodeName != "Continuity Check Message (CCM)" {
		t.Fatalf("opcode = %q", r.OpcodeName)
	}
	if r.RDI == nil || !*r.RDI {
		t.Errorf("RDI = %v, want true", r.RDI)
	}
	if r.Period == nil || *r.Period != 4 || r.PeriodName != "1s" {
		t.Errorf("period = %v/%q", r.Period, r.PeriodName)
	}
	if r.SeqNum == nil || *r.SeqNum != 0xdeadbeef {
		t.Errorf("seq = %v", r.SeqNum)
	}
	if r.MEPID == nil || *r.MEPID != 8191 {
		t.Errorf("mep id = %v, want 8191", r.MEPID)
	}
	if r.MEGID != "ICC-MEG-0001" {
		t.Errorf("meg id = %q, want ICC-MEG-0001", r.MEGID)
	}
}

func TestDecodeLBM(t *testing.T) {
	// OAM(mel=2, opcode=3 LBM, flags=0, trans_id=0) — body surfaced raw.
	const v = "400300040000000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MDLevel != 2 || r.OpcodeName != "Loopback Message (LBM)" {
		t.Fatalf("mel/op = %d/%q", r.MDLevel, r.OpcodeName)
	}
	if r.SeqNum != nil {
		t.Error("LBM should not decode a CCM sequence number")
	}
	if r.BodyHex == "" {
		t.Error("LBM body should be surfaced raw")
	}
}

func TestDecodeOpcodeNames(t *testing.T) {
	for _, tc := range []struct {
		hex  string
		want string
	}{
		{"00280004", "Ring-Automatic Protection Switching (R-APS)"},
		{"00050004", "Linktrace Message (LTM)"},
		{"00210004", "Alarm Indication Signal (AIS)"},
	} {
		r, err := Decode(tc.hex)
		if err != nil {
			t.Fatalf("Decode(%s): %v", tc.hex, err)
		}
		if r.OpcodeName != tc.want {
			t.Errorf("opcode name = %q, want %q", r.OpcodeName, tc.want)
		}
	}
}

func TestDecodeTLVSplit(t *testing.T) {
	// tlv_offset 4, then a 4-byte body, then trailing TLV bytes.
	const v = "0003000400000000" + "0203AABBCC"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TLVHex != "0203AABBCC" {
		t.Errorf("tlv hex = %q", r.TLVHex)
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("0001"); err == nil {
		t.Fatal("expected error on short header")
	}
}

func TestDecodePrintableRun(t *testing.T) {
	if got := printableASCII([]byte{0x20, 0x06, 'A', 'B', 'C', 0x00}); got != "ABC" {
		t.Errorf("printableASCII = %q, want ABC", got)
	}
	if got := printableASCII([]byte{0x00, 0x01, 'X', 0x00}); got != "" {
		t.Errorf("printableASCII (1 char) = %q, want empty", got)
	}
}
