// SPDX-License-Identifier: AGPL-3.0-or-later

package iso14443b

import "testing"

func TestDecodeATQB(t *testing.T) {
	// 50 | PUPI=11223344 | appdata=55667788 | proto: 00 71 85
	//   b[10]=0x71 -> FSCI 7 (128 bytes), protocol-type bit set (ISO 14443-4)
	//   b[11]=0x85 -> FWI 8, FO bits 01 -> NAD supported, CID not.
	a, err := DecodeATQB("50 11223344 55667788 00 71 85")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Valid {
		t.Error("0x50 leading byte should be valid")
	}
	if a.PUPI != "11223344" || a.ApplicationData != "55667788" {
		t.Errorf("PUPI/appdata: %q %q", a.PUPI, a.ApplicationData)
	}
	if a.FSCI != 7 || a.MaxFrameSizeBytes != 128 {
		t.Errorf("FSCI/frame: %d %d", a.FSCI, a.MaxFrameSizeBytes)
	}
	if !a.SupportsISO14443_4 {
		t.Error("protocol-type bit set -> ISO 14443-4 expected")
	}
	if a.FWI != 8 {
		t.Errorf("FWI = %d, want 8", a.FWI)
	}
	if !a.NADSupported || a.CIDSupported {
		t.Errorf("FO bits: NAD=%v CID=%v, want NAD=true CID=false", a.NADSupported, a.CIDSupported)
	}
}

func TestDecodeATQB_BitRate(t *testing.T) {
	// b[9]=0x77 -> same-bitrate? 0x80 not set; PICC->PCD 848/424/212 (0x70),
	// PCD->PICC 848/424/212 (0x07).
	a, err := DecodeATQB("50000000000000000077 00 00")
	if err != nil {
		t.Fatal(err)
	}
	if a.BitRate == nil || len(a.BitRate.PICCtoPCD) != 3 || len(a.BitRate.PCDtoPICC) != 3 {
		t.Errorf("bitrate decode: %+v", a.BitRate)
	}
}

func TestDecodeATQB_NonStandard(t *testing.T) {
	a, err := DecodeATQB("00112233445566778899AABB")
	if err != nil {
		t.Fatal(err)
	}
	if a.Valid || len(a.Notes) == 0 {
		t.Errorf("non-0x50 ATQB should be flagged: %+v", a)
	}
}

func TestDecodeATQB_CRCTolerated(t *testing.T) {
	// 14 bytes = 12 ATQB + 2 CRC_B.
	a, err := DecodeATQB("50112233445566778800718512AB")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Valid || len(a.Notes) == 0 {
		t.Errorf("14-byte ATQB should parse + note CRC: %+v", a)
	}
}

func TestDecodeATQB_Errors(t *testing.T) {
	if _, err := DecodeATQB("5011"); err == nil {
		t.Error("short ATQB should error")
	}
	if _, err := DecodeATQB("zzzz"); err == nil {
		t.Error("non-hex should error")
	}
}
