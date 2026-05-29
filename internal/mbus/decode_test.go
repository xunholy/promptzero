// SPDX-License-Identifier: AGPL-3.0-or-later

package mbus

import "testing"

// TestDecode_ACK pins the single-character acknowledgement.
func TestDecode_ACK(t *testing.T) {
	got, err := Decode("E5")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameType != "ACK (single character)" {
		t.Errorf("FrameType = %q", got.FrameType)
	}
}

// TestDecode_ShortSNDNKE is the master's initialise-slave frame.
//
//	10 40 01 41 16  (C=SND_NKE, A=1, checksum 0x41)
func TestDecode_ShortSNDNKE(t *testing.T) {
	got, err := Decode("10 40 01 41 16")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameType != "short" {
		t.Errorf("FrameType = %q; want short", got.FrameType)
	}
	if got.CFieldName != "SND_NKE (initialise slave)" {
		t.Errorf("CFieldName = %q", got.CFieldName)
	}
	if got.Direction != "master → slave (calling)" {
		t.Errorf("Direction = %q", got.Direction)
	}
	if got.AddressType != "primary address" {
		t.Errorf("AddressType = %q", got.AddressType)
	}
	if got.ChecksumValid == nil || !*got.ChecksumValid {
		t.Error("ChecksumValid = false; want true")
	}
}

// TestDecode_ShortREQUD2Broadcast exercises the broadcast address.
//
//	10 5B FE 59 16  (C=REQ_UD2, A=254 broadcast, checksum 0x59)
func TestDecode_ShortREQUD2Broadcast(t *testing.T) {
	got, err := Decode("10 5B FE 59 16")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.CFieldName != "REQ_UD2 (request class 2 data, FCB=0)" {
		t.Errorf("CFieldName = %q", got.CFieldName)
	}
	if got.AddressType != "broadcast (slaves reply)" {
		t.Errorf("AddressType = %q", got.AddressType)
	}
}

// TestDecode_ControlFrame is a 9-byte control frame (L==3, no data).
//
//	68 03 03 68 53 01 51 A5 16  (SND_UD, A=1, CI=data-send)
func TestDecode_ControlFrame(t *testing.T) {
	got, err := Decode("68 03 03 68 53 01 51 A5 16")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameType != "control" {
		t.Errorf("FrameType = %q; want control", got.FrameType)
	}
	if got.CIFieldName != "Data send (command to meter)" {
		t.Errorf("CIFieldName = %q", got.CIFieldName)
	}
	if got.ChecksumValid == nil || !*got.ChecksumValid {
		t.Error("ChecksumValid = false; want true")
	}
}

// TestDecode_LongWaterMeterResponse is the high-value case: an RSP_UD
// long frame with a Variable Data Structure long header identifying a
// water meter, plus trailing data-record bytes.
//
//	68 13 13 68 08 01 72  (RSP_UD, A=1, CI=long-header variable data)
//	78 56 34 12           ident BCD → serial 12345678
//	A7 32                 manufacturer LE → "LUG"
//	01 07                 version 1, medium 0x07 (Water)
//	2A 00 00 00           access 42, status 0, signature 0000
//	0C 13 15 31           data records (not decoded)
//	FF 16                 checksum 0xFF, stop
func TestDecode_LongWaterMeterResponse(t *testing.T) {
	got, err := Decode("68 13 13 68 08 01 72 78 56 34 12 A7 32 01 07 2A 00 00 00 0C 13 15 31 FF 16")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FrameType != "long" {
		t.Errorf("FrameType = %q; want long", got.FrameType)
	}
	if got.CFieldName != "RSP_UD (response, user data)" {
		t.Errorf("CFieldName = %q", got.CFieldName)
	}
	if got.Direction != "slave → master (replying)" {
		t.Errorf("Direction = %q", got.Direction)
	}
	if got.ChecksumValid == nil || !*got.ChecksumValid {
		t.Error("ChecksumValid = false; want true")
	}
	if got.Header == nil {
		t.Fatal("Header nil")
	}
	h := got.Header
	if h.SerialNumber != "12345678" {
		t.Errorf("SerialNumber = %q; want 12345678", h.SerialNumber)
	}
	if h.Manufacturer != "LUG" {
		t.Errorf("Manufacturer = %q; want LUG", h.Manufacturer)
	}
	if h.MediumName != "Water" {
		t.Errorf("MediumName = %q; want Water", h.MediumName)
	}
	if h.AccessNumber != 42 {
		t.Errorf("AccessNumber = %d; want 42", h.AccessNumber)
	}
	if got.DataRecordsHex != "0C131531" {
		t.Errorf("DataRecordsHex = %q; want 0C131531", got.DataRecordsHex)
	}
}

// TestDecode_BadChecksumNotedNotError confirms a checksum mismatch is
// surfaced (ChecksumValid=false + note) rather than rejected — an
// operator still wants the decoded fields off a corrupt capture.
func TestDecode_BadChecksumNotedNotError(t *testing.T) {
	// Short frame with a deliberately wrong checksum byte (0x00).
	got, err := Decode("10 40 01 00 16")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ChecksumValid == nil || *got.ChecksumValid {
		t.Error("ChecksumValid = true; want false")
	}
	if len(got.Notes) == 0 {
		t.Error("expected a checksum note")
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"bad hex":            "zz",
		"bad start byte":     "FF 00 11",
		"short wrong length": "10 40 01 41",    // missing stop byte
		"short no stop":      "10 40 01 41 FF", // 5 bytes but stop != 0x16
		"L mismatch":         "68 03 04 68 53 01 51 A5 16",
		"length mismatch":    "68 03 03 68 53 01 51 A5 16 00", // extra byte
		"no second start":    "68 03 03 FF 53 01 51 A5 16",
		"long no stop":       "68 03 03 68 53 01 51 A5 FF",
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestManufacturerCode(t *testing.T) {
	// "LUG" = (12<<10)|(21<<5)|7 = 0x32A7.
	if got := manufacturerCode(0x32A7); got != "LUG" {
		t.Errorf("manufacturerCode(0x32A7) = %q; want LUG", got)
	}
	// All-bits-set yields letters out of A-Z range → empty.
	if got := manufacturerCode(0xFFFF); got != "" {
		t.Errorf("manufacturerCode(0xFFFF) = %q; want empty", got)
	}
}
