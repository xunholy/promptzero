package applecontinuity

import (
	"strings"
	"testing"
)

func TestDecode_IBeacon(t *testing.T) {
	// Type 0x02 iBeacon, length 21:
	// UUID (16) + Major (2 BE) + Minor (2 BE) + TxPower (int8).
	// UUID f8e8a3a3-5b1a-4d4e-8b8e-1f1f1f1f1f1f
	// Major 100 (0x0064), Minor 200 (0x00C8), TxPower -58 (0xC6).
	in := "02 15 F8E8A3A35B1A4D4E8B8E1F1F1F1F1F1F 0064 00C8 C6"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageCnt != 1 {
		t.Fatalf("expected 1 message, got %d", r.MessageCnt)
	}
	m := r.Messages[0]
	if m.TypeName != "iBeacon" {
		t.Errorf("type name: %q", m.TypeName)
	}
	if m.IBeacon == nil {
		t.Fatal("iBeacon body nil")
	}
	if m.IBeacon.UUID != "F8E8A3A3-5B1A-4D4E-8B8E-1F1F1F1F1F1F" {
		t.Errorf("UUID: %q", m.IBeacon.UUID)
	}
	if m.IBeacon.Major != 100 || m.IBeacon.Minor != 200 {
		t.Errorf("Major/Minor: %d / %d", m.IBeacon.Major, m.IBeacon.Minor)
	}
	if m.IBeacon.TXPower != -58 {
		t.Errorf("TxPower: %d", m.IBeacon.TXPower)
	}
}

func TestDecode_NearbyInfo_FullEnvelope(t *testing.T) {
	// Full AD-record envelope:
	// 0x0A length, 0xFF type, 0x4C00 Apple ID, then TLV.
	// TLV: 0x10 Nearby Info, length 5. Body:
	// 0x83 (StatusFlags=8 PrimaryiCloud, ActionCode=3 iOS Lock)
	// 0x00 (DataFlags), 0xABCDEF (AuthTag).
	in := "0A FF 4C00 10 05 83 00 ABCDEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OuterFormat != "ad_record" {
		t.Errorf("outer_format: %q", r.OuterFormat)
	}
	m := r.Messages[0]
	if m.NearbyInfo == nil {
		t.Fatal("NearbyInfo nil")
	}
	if m.NearbyInfo.StatusFlags != 8 {
		t.Errorf("status_flags: %d", m.NearbyInfo.StatusFlags)
	}
	if m.NearbyInfo.ActionCode != 3 || m.NearbyInfo.ActionName != "iOS Lock Screen" {
		t.Errorf("action: %d %q", m.NearbyInfo.ActionCode, m.NearbyInfo.ActionName)
	}
	if !strings.Contains(m.NearbyInfo.StatusBits, "PrimaryiCloud") {
		t.Errorf("status_bits: %q", m.NearbyInfo.StatusBits)
	}
	if m.NearbyInfo.AuthTagHex != "ABCDEF" {
		t.Errorf("auth_tag: %q", m.NearbyInfo.AuthTagHex)
	}
}

func TestDecode_ManufacturerDataEnvelope(t *testing.T) {
	// Just 0x4C00 + TLV (no leading AD-record header).
	in := "4C00 10 05 53 00 112233"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OuterFormat != "manufacturer_data" {
		t.Errorf("outer_format: %q", r.OuterFormat)
	}
	if r.Messages[0].NearbyInfo.StatusFlags != 5 {
		t.Errorf("status_flags: %d", r.Messages[0].NearbyInfo.StatusFlags)
	}
}

func TestDecode_RawTLV(t *testing.T) {
	// Raw TLV with no envelope at all.
	in := "10 05 12 00 AABBCC"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OuterFormat != "raw_tlv" {
		t.Errorf("outer_format: %q", r.OuterFormat)
	}
}

func TestDecode_MultiTLV(t *testing.T) {
	// Two TLVs back-to-back: Nearby Info + Handoff.
	// TLV1: 10 05 83 00 ABCDEF (Nearby Info)
	// TLV2: 0C 0E 08 1234 56 78909A8B7C6D5E4F3A2B (Handoff)
	in := "10 05 83 00 ABCDEF 0C 0E 08 1234 56 78909A8B7C6D5E4F3A2B"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageCnt != 2 {
		t.Fatalf("expected 2 messages, got %d", r.MessageCnt)
	}
	if r.Summary != "Nearby Info + Handoff" {
		t.Errorf("summary: %q", r.Summary)
	}
	if r.Messages[1].Handoff == nil {
		t.Fatal("Handoff body nil")
	}
	if r.Messages[1].Handoff.IVHex != "1234" {
		t.Errorf("IV: %q", r.Messages[1].Handoff.IVHex)
	}
	if r.Messages[1].Handoff.AuthTagHex != "56" {
		t.Errorf("AuthTag: %q", r.Messages[1].Handoff.AuthTagHex)
	}
	if r.Messages[1].Handoff.PayloadHex != "78909A8B7C6D5E4F3A2B" {
		t.Errorf("payload: %q", r.Messages[1].Handoff.PayloadHex)
	}
}

func TestDecode_NearbyAction_WifiPassword(t *testing.T) {
	// 0x0F Nearby Action, length 5:
	// ActionFlags 0xC0, ActionType 0x08 (Wi-Fi Password), AuthTag 3 bytes.
	in := "0F 05 C0 08 112233"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	m := r.Messages[0]
	if m.NearbyAction == nil {
		t.Fatal("NearbyAction nil")
	}
	if m.NearbyAction.ActionType != 8 ||
		m.NearbyAction.ActionTypeName != "Wi-Fi Password" {
		t.Errorf("action: %d %q", m.NearbyAction.ActionType, m.NearbyAction.ActionTypeName)
	}
	if m.NearbyAction.AuthTagHex != "112233" {
		t.Errorf("AuthTag: %q", m.NearbyAction.AuthTagHex)
	}
}

func TestDecode_AirDrop(t *testing.T) {
	// 0x04 AirDrop, length 9: status + 8-byte identifier.
	in := "04 09 08 0102030405060708"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	m := r.Messages[0]
	if m.AirDrop == nil {
		t.Fatal("AirDrop nil")
	}
	if m.AirDrop.StatusHex != "08" {
		t.Errorf("status: %q", m.AirDrop.StatusHex)
	}
	if m.AirDrop.IdentifierHex != "0102030405060708" {
		t.Errorf("identifier: %q", m.AirDrop.IdentifierHex)
	}
}

func TestDecode_HeySiri(t *testing.T) {
	// 0x07 Hey Siri, length 5: 5 hash bytes.
	in := "07 05 AABBCCDDEE"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Messages[0].HeySiri == nil ||
		r.Messages[0].HeySiri.HashHex != "AABBCCDDEE" {
		t.Errorf("HeySiri: %+v", r.Messages[0].HeySiri)
	}
}

func TestDecode_ProximityPairing(t *testing.T) {
	// 0x06 Proximity Pairing (AirPods family). 10-byte body:
	// 00 0220 55 99 33 01 + filler.
	// DeviceModel 0x0220 (AirPods Pro), Battery 9/9 = 90/90,
	// Case 30%, Lid 0x01.
	in := "06 0A 00 0220 55 99 33 01 ABCDEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	p := r.Messages[0].ProxPairing
	if p == nil {
		t.Fatal("ProxPairing nil")
	}
	if p.DeviceModel != 0x0220 {
		t.Errorf("model: 0x%X", p.DeviceModel)
	}
	if p.BatteryLeft != 90 || p.BatteryRight != 90 {
		t.Errorf("battery L/R: %d / %d", p.BatteryLeft, p.BatteryRight)
	}
	if p.BatteryCase != 30 {
		t.Errorf("battery case: %d", p.BatteryCase)
	}
}

func TestDecode_UnknownTypeStillSurfacesHex(t *testing.T) {
	// 0x08 AirPlay Source — we don't decode the body fields,
	// but the type name + raw hex must be present.
	in := "08 04 AABBCCDD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	m := r.Messages[0]
	if m.TypeName != "AirPlay Source" {
		t.Errorf("type name: %q", m.TypeName)
	}
	if m.BodyHex != "AABBCCDD" {
		t.Errorf("body hex: %q", m.BodyHex)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"odd hex":       "10058",
		"bad hex":       "Z0058",
		"truncated TLV": "1005 8300",
		"no envelope":   "DEADBEEF",
		"truncated AD":  "0AFF 4C00 1005",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestNearbyStatusBitsTable(t *testing.T) {
	if nearbyStatusBits(0) != "(no status bits set)" {
		t.Errorf("zero: %q", nearbyStatusBits(0))
	}
	got := nearbyStatusBits(0xF)
	for _, want := range []string{"PrimaryiCloud", "AirDrop", "AutoUnlockActive", "AutoUnlockEnabled"} {
		if !strings.Contains(got, want) {
			t.Errorf("0xF missing %q in %q", want, got)
		}
	}
}
