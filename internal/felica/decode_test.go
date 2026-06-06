// SPDX-License-Identifier: AGPL-3.0-or-later

package felica

import "testing"

// Vectors are hand-built per the FeliCa frame layout (JIS X 6319-4 / Sony
// FeliCa Card User's Manual): LEN + code + (IDm) + per-code fixed fields.
// The structural walk is byte-checkable.

func TestPollingCommand(t *testing.T) {
	// LEN 6, code 0x00, systemCode FFFF (wildcard), requestCode 01, timeSlot 00.
	r, err := Decode("0600ffff0100")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Code != 0x00 || r.CodeName != "Polling (command)" {
		t.Errorf("code = 0x%02X/%q", r.Code, r.CodeName)
	}
	if r.IsResponse {
		t.Error("polling command should not be a response")
	}
	if r.SystemCodeRequested != "FFFF" {
		t.Errorf("SystemCodeRequested = %q", r.SystemCodeRequested)
	}
	if r.RequestCode == nil || *r.RequestCode != 1 || r.RequestCodeName != "system code request" {
		t.Errorf("RequestCode = %v/%q", r.RequestCode, r.RequestCodeName)
	}
	if r.TimeSlot == nil || *r.TimeSlot != 0 {
		t.Errorf("TimeSlot = %v", r.TimeSlot)
	}
	if r.IDm != "" {
		t.Errorf("polling command must not have an IDm, got %q", r.IDm)
	}
}

func TestPollingResponseWithSystemCode(t *testing.T) {
	// LEN 0x14, code 0x01, IDm 0101.., PMm 0103.., requestData/systemCode 12FC (NDEF).
	r, err := Decode("140101010101010101010103988877665544" + "12fc")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CodeName != "Polling (response)" || !r.IsResponse {
		t.Errorf("code = %q resp=%v", r.CodeName, r.IsResponse)
	}
	if r.IDm != "0101010101010101" {
		t.Errorf("IDm = %q", r.IDm)
	}
	if r.ManufacturerCode != "0101" {
		t.Errorf("ManufacturerCode = %q", r.ManufacturerCode)
	}
	if r.PMm != "0103988877665544" {
		t.Errorf("PMm = %q", r.PMm)
	}
	if r.ICCode != "0103" {
		t.Errorf("ICCode = %q", r.ICCode)
	}
	if r.SystemCode != "12FC" || r.SystemCodeName != "NFC Forum Type 3 Tag (NDEF)" {
		t.Errorf("SystemCode = %q/%q", r.SystemCode, r.SystemCodeName)
	}
}

func TestReadWithoutEncryptionResponseSuccess(t *testing.T) {
	// LEN 0x1D, code 0x07, IDm, SF1 00 (ok), SF2 00, 1 block.
	r, err := Decode("1d070102030405060708000001aabbccddeeff00112233445566778899")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CodeName != "Read Without Encryption (response)" {
		t.Errorf("CodeName = %q", r.CodeName)
	}
	if r.IDm != "0102030405060708" {
		t.Errorf("IDm = %q", r.IDm)
	}
	if r.StatusOK == nil || !*r.StatusOK {
		t.Errorf("StatusOK = %v, want true", r.StatusOK)
	}
	if r.NumBlocks == nil || *r.NumBlocks != 1 {
		t.Fatalf("NumBlocks = %v", r.NumBlocks)
	}
	if len(r.Blocks) != 1 || r.Blocks[0] != "AABBCCDDEEFF00112233445566778899" {
		t.Errorf("Blocks = %v", r.Blocks)
	}
}

func TestReadResponseError(t *testing.T) {
	// SF1 != 0x00 → error, no block data parsed.
	r, err := Decode("0c070102030405060708" + "01a6")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.StatusOK == nil || *r.StatusOK {
		t.Error("StatusOK should be false")
	}
	if r.StatusFlag1 == nil || *r.StatusFlag1 != 1 || r.StatusFlag2 == nil || *r.StatusFlag2 != 0xA6 {
		t.Errorf("status = %v/%v", r.StatusFlag1, r.StatusFlag2)
	}
	if len(r.Blocks) != 0 {
		t.Errorf("error response must not yield blocks, got %v", r.Blocks)
	}
}

func TestRequestSystemCodeResponse(t *testing.T) {
	// LEN 0x0F, code 0x0D, IDm, n=2, system codes 12FC + 88B4.
	r, err := Decode("0f0d0102030405060708" + "02" + "12fc" + "88b4")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CodeName != "Request System Code (response)" {
		t.Errorf("CodeName = %q", r.CodeName)
	}
	want := []string{"12FC", "88B4"}
	if len(r.SystemCodes) != 2 || r.SystemCodes[0] != want[0] || r.SystemCodes[1] != want[1] {
		t.Errorf("SystemCodes = %v, want %v", r.SystemCodes, want)
	}
}

func TestGenericCommandSurfacesIDm(t *testing.T) {
	// Request Service (0x02): IDm + raw payload.
	r, err := Decode("0e020102030405060708" + "0109ff")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CodeName != "Request Service (command)" {
		t.Errorf("CodeName = %q", r.CodeName)
	}
	if r.IDm != "0102030405060708" {
		t.Errorf("IDm = %q", r.IDm)
	}
	if r.PayloadHex != "0109FF" {
		t.Errorf("PayloadHex = %q", r.PayloadHex)
	}
}

func TestRejectUnknownCode(t *testing.T) {
	// 0xFE is not a FeliCa command/response code.
	if _, err := Decode("02fe"); err == nil {
		t.Error("expected rejection of unknown code 0xFE")
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "06", "zz"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
