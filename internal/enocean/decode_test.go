// SPDX-License-Identifier: AGPL-3.0-or-later

package enocean

import (
	"encoding/hex"
	"testing"
)

// canonicalRPS is an ESP3 RADIO_ERP1 frame carrying an RPS (rocker
// switch) telegram from sender 0029289C: sync 0x55, data length 7,
// optional length 7, packet type 1, header CRC-8 0x7A, data CRC-8 0xDD.
// The CRC-8s are the EnOcean standard (poly 0x07).
const canonicalRPS = "55000707017AF6300029289C3003FFFFFFFF3D00DD"

func TestDecodeRPSFrame(t *testing.T) {
	r, err := Decode(canonicalRPS)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.SyncByteOK {
		t.Error("sync byte not OK")
	}
	if r.DataLength != 7 || r.OptionalLength != 7 || r.PacketType != 1 {
		t.Errorf("lengths/type = %d/%d/%d", r.DataLength, r.OptionalLength, r.PacketType)
	}
	if r.PacketTypeName != "RADIO_ERP1" {
		t.Errorf("type name = %q", r.PacketTypeName)
	}
	if !r.HeaderCRC8Valid || !r.DataCRC8Valid {
		t.Errorf("CRC valid = %v/%v (header %s, data %s)", r.HeaderCRC8Valid, r.DataCRC8Valid, r.HeaderCRC8, r.DataCRC8)
	}
	if r.Radio == nil {
		t.Fatal("no radio telegram")
	}
	if r.Radio.RORG != "0xF6" || r.Radio.RORGName[:3] != "RPS" {
		t.Errorf("rorg = %s / %q", r.Radio.RORG, r.Radio.RORGName)
	}
	if r.Radio.SenderID != "0029289C" {
		t.Errorf("sender = %q, want 0029289C", r.Radio.SenderID)
	}
	if r.Radio.PayloadHex != "30" || r.Radio.Status != "0x30" {
		t.Errorf("payload/status = %q/%q", r.Radio.PayloadHex, r.Radio.Status)
	}
	if r.Radio.Optional == nil {
		t.Fatal("no optional data")
	}
	o := r.Radio.Optional
	if o.SubTelegramNum != 3 || o.DestinationID != "FFFFFFFF" || o.RSSIdBm != -61 || o.SecurityLevel != 0 {
		t.Errorf("optional = %+v, want subtel 3 / dest FFFFFFFF / rssi -61 / sec 0", o)
	}
}

func TestCRC8KnownVectors(t *testing.T) {
	// Header [00 07 07 01] -> 0x7A.
	if got := crc8([]byte{0x00, 0x07, 0x07, 0x01}); got != 0x7A {
		t.Errorf("header CRC8 = 0x%02X, want 0x7A", got)
	}
	// Data+optional -> 0xDD.
	body, _ := hex.DecodeString("F6300029289C3003FFFFFFFF3D00")
	if got := crc8(body); got != 0xDD {
		t.Errorf("data CRC8 = 0x%02X, want 0xDD", got)
	}
}

func TestDecodeCorruptCRC(t *testing.T) {
	// Flip the last byte (data CRC) — must report invalid, not error.
	r, err := Decode("55000707017AF6300029289C3003FFFFFFFF3D00DE")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.DataCRC8Valid {
		t.Error("expected data_crc8_valid=false for a corrupted CRC")
	}
	if r.HeaderCRC8Valid != true {
		t.Error("header CRC should still be valid")
	}
}

func TestDecode1BSContact(t *testing.T) {
	// A 1BS (D5) contact telegram; just confirm RORG naming + framing.
	hdr := []byte{0x00, 0x07, 0x07, 0x01}
	data := []byte{0xD5, 0x08, 0x01, 0x82, 0x5D, 0xAB, 0x00} // RORG D5, payload 08, sender 01825DAB, status 00
	opt := []byte{0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x2D, 0x00}
	frame := append([]byte{0x55}, hdr...)
	frame = append(frame, crc8(hdr))
	frame = append(frame, data...)
	frame = append(frame, opt...)
	frame = append(frame, crc8(append(append([]byte{}, data...), opt...)))
	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.DataCRC8Valid || r.Radio == nil || r.Radio.RORG != "0xD5" {
		t.Errorf("1BS decode = %+v", r.Radio)
	}
	if r.Radio.SenderID != "01825DAB" || r.Radio.Optional.RSSIdBm != -45 {
		t.Errorf("sender/rssi = %q/%d", r.Radio.SenderID, r.Radio.Optional.RSSIdBm)
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "55", "00000000017A", "AA000707017A"} {
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

// FuzzDecode asserts the parser never panics.
func FuzzDecode(f *testing.F) {
	f.Add(canonicalRPS)
	f.Add("55")
	f.Add("")
	f.Add("5500FF0001AA")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
