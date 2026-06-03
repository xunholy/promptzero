// SPDX-License-Identifier: AGPL-3.0-or-later

package fdxb

import "testing"

// Vector 1 (real Proxmark3 decode): country 999 / national 1500030037,
// CRC 0x8A1C. The 8 ID bytes (AA 25 16 9A 03 9F 00 00) reconstruct that
// national+country; the CRC stored LSB-first in bytes 8-9 is 38 51.
func TestDecode_Vector999_CRCValid(t *testing.T) {
	f, err := DecodeHex("AA 25 16 9A 03 9F 00 00 38 51")
	if err != nil {
		t.Fatal(err)
	}
	if f.NationalCode != 1500030037 {
		t.Errorf("national = %d, want 1500030037", f.NationalCode)
	}
	if f.CountryCode != 999 {
		t.Errorf("country = %d, want 999", f.CountryCode)
	}
	if f.CRCComputed != "0x8A1C" {
		t.Errorf("crc computed = %s, want 0x8A1C", f.CRCComputed)
	}
	if f.CRCStored != "0x8A1C" {
		t.Errorf("crc stored = %s, want 0x8A1C", f.CRCStored)
	}
	if f.CRCValid == nil || !*f.CRCValid {
		t.Errorf("crc should be valid: %v", f.CRCValid)
	}
	if f.CountryNote == "" {
		t.Errorf("999 should be flagged as test/unregistered range")
	}
}

// Vector 2 (real Proxmark3 decode): country 528 (Netherlands) / national
// 140000795552, raw ID block 05 D9 4D 19 04 21 00 01.
func TestDecode_Vector528_IDOnly(t *testing.T) {
	f, err := DecodeHex("05D94D190421 0001")
	if err != nil {
		t.Fatal(err)
	}
	if f.NationalCode != 140000795552 {
		t.Errorf("national = %d, want 140000795552", f.NationalCode)
	}
	if f.CountryCode != 528 {
		t.Errorf("country = %d, want 528", f.CountryCode)
	}
	// 8-byte input -> CRC not validated, note present.
	if f.CRCValid != nil {
		t.Errorf("CRC should not be validated for an 8-byte block")
	}
	if len(f.Notes) == 0 {
		t.Errorf("8-byte block should note missing CRC")
	}
	if f.CountryNote != "" {
		t.Errorf("528 is a real ISO country, should carry no manufacturer/test note")
	}
}

func TestDecode_CRCMismatch(t *testing.T) {
	// Corrupt the stored CRC of the 999 vector.
	f, err := DecodeHex("AA 25 16 9A 03 9F 00 00 FF FF")
	if err != nil {
		t.Fatal(err)
	}
	if f.CRCValid == nil || *f.CRCValid {
		t.Errorf("corrupt CRC should be invalid")
	}
	// Computed CRC is still the real one (over the unchanged ID block).
	if f.CRCComputed != "0x8A1C" {
		t.Errorf("computed crc = %s, want 0x8A1C", f.CRCComputed)
	}
}

func TestDecode_Extended(t *testing.T) {
	f, err := DecodeHex("AA25169A039F0000 3851 ABCDEF")
	if err != nil {
		t.Fatal(err)
	}
	if f.ExtendedHex != "ABCDEF" {
		t.Errorf("extended = %q, want ABCDEF", f.ExtendedHex)
	}
	if f.CRCValid == nil || !*f.CRCValid {
		t.Errorf("13-byte block should still validate CRC")
	}
}

func TestDecode_Errors(t *testing.T) {
	if _, err := DecodeHex("AABBCC"); err == nil {
		t.Error("sub-8-byte block should error")
	}
	if _, err := DecodeHex(""); err == nil {
		t.Error("empty should error")
	}
	if _, err := DecodeHex("zzzz"); err == nil {
		t.Error("non-hex should error")
	}
}
