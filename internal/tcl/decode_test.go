// SPDX-License-Identifier: AGPL-3.0-or-later

package tcl

import "testing"

// Vectors use the canonical ISO 14443-4 §7.1 PCB values (cross-checked vs
// Proxmark / libnfc): I-block 0x02 / chaining 0x12, R(ACK) 0xA2 / R(NAK) 0xB2,
// S(DESELECT) 0xC2 / S(WTX) 0xF2, CID bit 0x08.

func TestIBlockWithAPDU(t *testing.T) {
	// PCB 0x02 (I-block, bn 0), INF = a SELECT APDU.
	r, err := Decode("0200a4040000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.BlockType != "I-block" {
		t.Errorf("BlockType = %q", r.BlockType)
	}
	if r.BlockNumber == nil || *r.BlockNumber != 0 {
		t.Errorf("BlockNumber = %v", r.BlockNumber)
	}
	if r.Chaining || r.CIDPresent || r.NADPresent {
		t.Errorf("unexpected flags: %+v", r)
	}
	if r.INFHex != "00A4040000" {
		t.Errorf("INFHex = %q", r.INFHex)
	}
}

func TestIBlockChaining(t *testing.T) {
	// PCB 0x13 = I-block, chaining, bn 1.
	r, err := Decode("130011")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Chaining {
		t.Error("Chaining should be true")
	}
	if r.BlockNumber == nil || *r.BlockNumber != 1 {
		t.Errorf("BlockNumber = %v, want 1", r.BlockNumber)
	}
	if r.INFHex != "0011" {
		t.Errorf("INFHex = %q", r.INFHex)
	}
}

func TestIBlockWithCID(t *testing.T) {
	// PCB 0x0A = I-block + CID present; CID byte 0x0C → cid 12.
	r, err := Decode("0a0c00a4")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.CIDPresent || r.CID == nil || *r.CID != 12 {
		t.Errorf("CID = %v present=%v", r.CID, r.CIDPresent)
	}
	if r.INFHex != "00A4" {
		t.Errorf("INFHex = %q", r.INFHex)
	}
}

func TestIBlockWithNAD(t *testing.T) {
	// PCB 0x06 = I-block + NAD present; NAD byte 0x51.
	r, err := Decode("065100a4")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.NADPresent || r.NAD == nil || *r.NAD != 0x51 {
		t.Errorf("NAD = %v present=%v", r.NAD, r.NADPresent)
	}
	if r.INFHex != "00A4" {
		t.Errorf("INFHex = %q", r.INFHex)
	}
}

func TestRBlockACK(t *testing.T) {
	r, err := Decode("a2")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.BlockType != "R-block" {
		t.Errorf("BlockType = %q", r.BlockType)
	}
	if r.ACK == nil || !*r.ACK {
		t.Errorf("ACK = %v, want true", r.ACK)
	}
	if r.BlockNumber == nil || *r.BlockNumber != 0 {
		t.Errorf("BlockNumber = %v", r.BlockNumber)
	}
}

func TestRBlockNAK(t *testing.T) {
	// 0xB3 = R(NAK), bn 1.
	r, err := Decode("b3")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ACK == nil || *r.ACK {
		t.Errorf("ACK = %v, want false (NAK)", r.ACK)
	}
	if r.BlockNumber == nil || *r.BlockNumber != 1 {
		t.Errorf("BlockNumber = %v, want 1", r.BlockNumber)
	}
}

func TestRBlockACKWithCID(t *testing.T) {
	// 0xAA = R(ACK) + CID; CID byte 0x00.
	r, err := Decode("aa00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.CIDPresent || r.CID == nil || *r.CID != 0 {
		t.Errorf("CID = %v present=%v", r.CID, r.CIDPresent)
	}
	if r.ACK == nil || !*r.ACK {
		t.Errorf("ACK = %v, want true", r.ACK)
	}
}

func TestSBlockDeselect(t *testing.T) {
	r, err := Decode("c2")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.BlockType != "S-block" || r.SBlockType != "DESELECT" {
		t.Errorf("S-block = %q/%q", r.BlockType, r.SBlockType)
	}
}

func TestSBlockWTX(t *testing.T) {
	// 0xF2 = S(WTX); INF byte 0x05 → WTXM 5.
	r, err := Decode("f205")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.SBlockType != "WTX" {
		t.Errorf("SBlockType = %q", r.SBlockType)
	}
	if r.WTXM == nil || *r.WTXM != 5 {
		t.Errorf("WTXM = %v, want 5", r.WTXM)
	}
}

func TestRFUBlock(t *testing.T) {
	// 0x42 = top bits 01 → RFU.
	r, err := Decode("42")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.BlockType != "RFU" {
		t.Errorf("BlockType = %q, want RFU", r.BlockType)
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz", "00", "0a"} {
		// empty, non-hex, invalid I-block (bit2 clear), CID promised but truncated
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
