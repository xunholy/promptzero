// SPDX-License-Identifier: AGPL-3.0-or-later

package btoob

import (
	"encoding/hex"
	"testing"
)

// ad builds one EIR/AD structure: (length, ad-type, data...).
func ad(adType byte, data ...byte) []byte {
	out := []byte{byte(1 + len(data)), adType}
	return append(out, data...)
}

func findRecord(t *testing.T, res *Result, adType int) map[string]any {
	t.Helper()
	if res.EIR == nil {
		t.Fatal("no EIR block")
	}
	for _, r := range res.EIR.Records {
		if r.ADType == adType {
			return r.Decoded
		}
	}
	t.Fatalf("AD type 0x%02X not found in EIR", adType)
	return nil
}

func TestDecodeBREDR(t *testing.T) {
	// 13 00 | BD_ADDR LE 06..01 | name "Hdst" | CoD 24:04:04 (Audio/Video)
	var b []byte
	b = append(b, 0x13, 0x00)                         // OOB Data Length = 19
	b = append(b, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01) // BD_ADDR (LE)
	b = append(b, ad(0x09, 'H', 'd', 's', 't')...)    // Complete Local Name
	b = append(b, ad(0x0D, 0x04, 0x04, 0x24)...)      // Class of Device

	res, err := DecodeBREDR(b)
	if err != nil {
		t.Fatal(err)
	}
	if res.Variant != "br_edr" {
		t.Errorf("variant = %q", res.Variant)
	}
	if res.DeviceAddress != "01:02:03:04:05:06" {
		t.Errorf("device address = %q", res.DeviceAddress)
	}
	if res.OOBDataLength == nil || *res.OOBDataLength != 19 {
		t.Errorf("oob length = %v, want 19", res.OOBDataLength)
	}
	if len(res.Notes) != 0 {
		t.Errorf("unexpected notes (length matched, should be silent): %v", res.Notes)
	}
	cod := findRecord(t, res, 0x0D)
	if cod["major_device_class_name"] != "Audio / Video" {
		t.Errorf("CoD major class = %v", cod["major_device_class_name"])
	}
	if cod["class_of_device_hex"] != "240404" {
		t.Errorf("CoD hex = %v", cod["class_of_device_hex"])
	}
	name := findRecord(t, res, 0x09)
	if name["name"] != "Hdst" {
		t.Errorf("local name = %v", name["name"])
	}
}

func TestDecodeLE(t *testing.T) {
	var b []byte
	// LE Bluetooth Device Address: addr LE 06..01 + type 0x01 (random)
	b = append(b, ad(0x1B, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x01)...)
	b = append(b, ad(0x1C, 0x02)...)     // LE Role: Peripheral/Central
	b = append(b, ad(0x09, 'L', 'E')...) // Complete Local Name

	res, err := DecodeLE(b)
	if err != nil {
		t.Fatal(err)
	}
	if res.Variant != "le" {
		t.Errorf("variant = %q", res.Variant)
	}
	addr := findRecord(t, res, 0x1B)
	if addr["address"] != "01:02:03:04:05:06" {
		t.Errorf("LE address = %v", addr["address"])
	}
	if addr["address_type"] != "random" {
		t.Errorf("LE address type = %v", addr["address_type"])
	}
	role := findRecord(t, res, 0x1C)
	if role["role"] != "Peripheral/Central (Peripheral preferred for connection)" {
		t.Errorf("LE role = %v", role["role"])
	}
}

func TestDecodeHexVariantRouting(t *testing.T) {
	leBytes := append(ad(0x1C, 0x01), ad(0x09, 'X')...)
	res, err := DecodeHex("le", hex.EncodeToString(leBytes))
	if err != nil {
		t.Fatal(err)
	}
	if res.Variant != "le" {
		t.Errorf("variant routing: %q", res.Variant)
	}
	// Default routes to BR/EDR.
	brBytes := []byte{0x08, 0x00, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	res2, err := DecodeHex("", "08:00:06:05:04:03:02:01")
	if err != nil {
		t.Fatal(err)
	}
	_ = brBytes
	if res2.Variant != "br_edr" || res2.DeviceAddress != "01:02:03:04:05:06" {
		t.Errorf("default-variant BR/EDR: %+v", res2)
	}
}

func TestBREDRLengthMismatchNoted(t *testing.T) {
	// Declared length 99 but only 8 bytes present.
	b := []byte{0x63, 0x00, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	res, err := DecodeBREDR(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notes) == 0 {
		t.Error("length mismatch should be noted")
	}
}

func TestLERoleReserved(t *testing.T) {
	res, err := DecodeLE(ad(0x1C, 0x07)) // 0x07 reserved
	if err != nil {
		t.Fatal(err)
	}
	role := findRecord(t, res, 0x1C)
	if role["role"] != "reserved (0x07)" {
		t.Errorf("reserved role handling: %v", role["role"])
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := DecodeBREDR([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Error("short BR/EDR record should error")
	}
	if _, err := DecodeHex("le", ""); err == nil {
		t.Error("empty hex should error")
	}
	if _, err := DecodeHex("le", "zz"); err == nil {
		t.Error("non-hex should error")
	}
}
