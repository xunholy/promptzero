package ble

import (
	"strings"
	"testing"
)

// TestDecode_NearbyInfo pins the canonical NearbyInfo payload
// shape — 5-byte TLV with status byte 0x1B (recent-interaction
// action code 0x0B), flags 0x18 (wifi_on + watch_unlocked), and a
// 3-byte auth tag. Vector mirrors the worked example in
// furiousMAC/continuity nearbyinfo.md.
func TestDecode_NearbyInfo(t *testing.T) {
	got, err := Decode("10051B18AABBCC")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Count != 1 {
		t.Fatalf("Count = %d; want 1", got.Count)
	}
	tlv := got.TLVs[0]
	if tlv.Type != 0x10 {
		t.Errorf("Type = 0x%02X; want 0x10", tlv.Type)
	}
	if tlv.Name != "NearbyInfo" {
		t.Errorf("Name = %q; want 'NearbyInfo'", tlv.Name)
	}
	if tlv.Length != 5 {
		t.Errorf("Length = %d; want 5", tlv.Length)
	}
	if tlv.Hex != "1B18AABBCC" {
		t.Errorf("Hex = %q; want '1B18AABBCC'", tlv.Hex)
	}
	if tlv.Fields["action_code"] != 0x0B {
		t.Errorf("action_code = %v; want 0x0B", tlv.Fields["action_code"])
	}
	if tlv.Fields["action_code_name"] != "Activity Level - Recent user interaction" {
		t.Errorf("action_code_name = %v", tlv.Fields["action_code_name"])
	}
	flags, ok := tlv.Fields["data_flags_decoded"].([]string)
	if !ok {
		t.Fatalf("data_flags_decoded missing or wrong type: %T", tlv.Fields["data_flags_decoded"])
	}
	wantFlags := []string{"wifi_on", "watch_unlocked"}
	if len(flags) != len(wantFlags) {
		t.Errorf("flags = %v; want %v", flags, wantFlags)
	}
}

// TestDecode_NearbyAction parses an Action 0x0F payload — flags
// 0x00, action_type 0x08 (WiFiPasswordRequest), 3-byte auth tag.
func TestDecode_NearbyAction(t *testing.T) {
	got, err := Decode("0F0500080A0B0C")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Count != 1 {
		t.Fatalf("Count = %d; want 1", got.Count)
	}
	tlv := got.TLVs[0]
	if tlv.Name != "NearbyAction" {
		t.Errorf("Name = %q", tlv.Name)
	}
	if tlv.Fields["action_type"] != 0x08 {
		t.Errorf("action_type = %v; want 0x08", tlv.Fields["action_type"])
	}
	if tlv.Fields["action_name"] != "WiFiPasswordRequest" {
		t.Errorf("action_name = %v", tlv.Fields["action_name"])
	}
}

// TestDecode_Handoff parses a Handoff payload — 14 bytes:
// clipboard byte + 2-byte IV + 1-byte auth tag + 10-byte encrypted.
func TestDecode_Handoff(t *testing.T) {
	got, err := Decode("0C0E01ABCDEF112233445566778899AA")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	tlv := got.TLVs[0]
	if tlv.Name != "Handoff" {
		t.Errorf("Name = %q", tlv.Name)
	}
	if tlv.Fields["clipboard_status"] != 0x01 {
		t.Errorf("clipboard_status = %v; want 0x01", tlv.Fields["clipboard_status"])
	}
	if tlv.Fields["sequence_iv"] != 0xABCD {
		t.Errorf("sequence_iv = %v; want 0xABCD", tlv.Fields["sequence_iv"])
	}
	if tlv.Fields["auth_tag"] != "EF" {
		t.Errorf("auth_tag = %v; want 'EF'", tlv.Fields["auth_tag"])
	}
	if tlv.Fields["encrypted"] != "112233445566778899AA" {
		t.Errorf("encrypted = %v", tlv.Fields["encrypted"])
	}
}

// TestDecode_ProximityPairing parses an AirPods Pro 2 ProximityPairing
// payload — verifies model lookup and battery-nibble decoding.
func TestDecode_ProximityPairing(t *testing.T) {
	// prefix=0x01, model=0x1420 (AirPods Pro 2nd gen), status=0x55,
	// battery_left=10 (100%), battery_right=8 (80%), battery_case=5 (50%)
	// + charging nibble 0, lid counter 0, color 0, reserved 0.
	got, err := Decode("0709011420 55 A8 50 00 00 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	tlv := got.TLVs[0]
	if tlv.Name != "ProximityPairing" {
		t.Errorf("Name = %q", tlv.Name)
	}
	if tlv.Fields["device_model"] != "1420" {
		t.Errorf("device_model = %v; want '1420'", tlv.Fields["device_model"])
	}
	if tlv.Fields["device_model_name"] != "AirPods Pro (2nd gen)" {
		t.Errorf("device_model_name = %v", tlv.Fields["device_model_name"])
	}
	left, _ := tlv.Fields["battery_left"].(map[string]any)
	if left["percent"] != 100 {
		t.Errorf("battery_left.percent = %v; want 100", left["percent"])
	}
	right, _ := tlv.Fields["battery_right"].(map[string]any)
	if right["percent"] != 80 {
		t.Errorf("battery_right.percent = %v; want 80", right["percent"])
	}
}

// TestDecode_AirDrop parses an AirDrop 18-byte advertisement —
// verifies the contact-hash slot extraction.
func TestDecode_AirDrop(t *testing.T) {
	// version=0x01, then 8 padding bytes, 4 contact-hash 16-bit slots,
	// suffix=0x00. Picked unique values to make sure slot offsets are
	// right.
	got, err := Decode("0512 01 0102030405060708 AAAA BBBB CCCC DDDD 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	tlv := got.TLVs[0]
	if tlv.Name != "AirDrop" {
		t.Errorf("Name = %q", tlv.Name)
	}
	if tlv.Fields["version"] != 0x01 {
		t.Errorf("version = %v; want 1", tlv.Fields["version"])
	}
	if tlv.Fields["appleid_hash"] != "AAAA" {
		t.Errorf("appleid_hash = %v; want 'AAAA'", tlv.Fields["appleid_hash"])
	}
	if tlv.Fields["phone_hash"] != "BBBB" {
		t.Errorf("phone_hash = %v; want 'BBBB'", tlv.Fields["phone_hash"])
	}
	if tlv.Fields["email_hash"] != "CCCC" {
		t.Errorf("email_hash = %v; want 'CCCC'", tlv.Fields["email_hash"])
	}
	if tlv.Fields["email2_hash"] != "DDDD" {
		t.Errorf("email2_hash = %v; want 'DDDD'", tlv.Fields["email2_hash"])
	}
}

// TestDecode_MultipleTLVs walks a payload with two TLVs (Handoff
// then NearbyInfo) and verifies both decode in order with the right
// offsets.
func TestDecode_MultipleTLVs(t *testing.T) {
	// Handoff (0C/14 bytes) then NearbyInfo (10/5 bytes).
	got, err := Decode("0C0E01ABCDEF112233445566778899AA10051B00AABBCC")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Count != 2 {
		t.Fatalf("Count = %d; want 2 TLVs", got.Count)
	}
	if got.TLVs[0].Name != "Handoff" {
		t.Errorf("TLVs[0].Name = %q", got.TLVs[0].Name)
	}
	if got.TLVs[1].Name != "NearbyInfo" {
		t.Errorf("TLVs[1].Name = %q", got.TLVs[1].Name)
	}
}

// TestDecode_ManufacturerPrefix accepts the 0x4C00 manufacturer-ID
// prefix and reports it via StrippedPrefix.
func TestDecode_ManufacturerPrefix(t *testing.T) {
	got, err := Decode("4C0010051B00AABBCC")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.StrippedPrefix != "manufacturer" {
		t.Errorf("StrippedPrefix = %q; want 'manufacturer'", got.StrippedPrefix)
	}
	if got.Count != 1 || got.TLVs[0].Name != "NearbyInfo" {
		t.Errorf("walk result wrong: %+v", got.TLVs)
	}
}

// TestDecode_FullADStructure accepts the full <len> FF 4C 00 ...
// AD-structure wrapper from raw BLE advertisement bytes.
func TestDecode_FullADStructure(t *testing.T) {
	// 0x0A length = 10 bytes that follow (FF + 4C 00 + 7-byte payload)
	// Payload: NearbyInfo TLV (10 05 1B 00 AA BB CC) = 7 bytes.
	got, err := Decode("0A FF 4C 00 10 05 1B 00 AA BB CC")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.StrippedPrefix != "ad_structure" {
		t.Errorf("StrippedPrefix = %q; want 'ad_structure'", got.StrippedPrefix)
	}
	if got.Count != 1 || got.TLVs[0].Name != "NearbyInfo" {
		t.Errorf("walk result wrong: %+v", got.TLVs)
	}
}

// TestDecode_NoPrefix verifies the parser reports "none" when the
// input is just bare TLV bytes (the form most operators pull from
// btmon).
func TestDecode_NoPrefix(t *testing.T) {
	got, err := Decode("10051B00AABBCC")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.StrippedPrefix != "none" {
		t.Errorf("StrippedPrefix = %q; want 'none'", got.StrippedPrefix)
	}
}

// TestDecode_TolerateSeparators confirms the parser strips ':' '-'
// '_' whitespace from the hex intake.
func TestDecode_TolerateSeparators(t *testing.T) {
	for _, in := range []string{
		"10:05:1B:00:AA:BB:CC",
		"10-05-1B-00-AA-BB-CC",
		"10_05_1B_00_AA_BB_CC",
		"  10 05 1B 00 AA BB CC  ",
	} {
		got, err := Decode(in)
		if err != nil {
			t.Errorf("Decode(%q): %v", in, err)
			continue
		}
		if got.Count != 1 {
			t.Errorf("Decode(%q): Count = %d", in, got.Count)
		}
	}
}

// TestDecode_UnknownTypeStillWalked confirms unknown action types
// render as "Unknown" without breaking the walk — the operator
// still sees the type byte + raw hex.
func TestDecode_UnknownTypeStillWalked(t *testing.T) {
	// 0xFE is not in the catalog; should still be parsed.
	got, err := Decode("FE03AABBCC")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Count != 1 {
		t.Fatalf("Count = %d", got.Count)
	}
	tlv := got.TLVs[0]
	if tlv.Type != 0xFE {
		t.Errorf("Type = 0x%02X; want 0xFE", tlv.Type)
	}
	if tlv.Name != "Unknown" {
		t.Errorf("Name = %q; want 'Unknown'", tlv.Name)
	}
	if tlv.Hex != "AABBCC" {
		t.Errorf("Hex = %q", tlv.Hex)
	}
	if tlv.Fields != nil {
		t.Errorf("Fields should be nil for unknown type, got %v", tlv.Fields)
	}
}

// TestDecode_ShortPayloadWarning surfaces a DecodeWarning when a
// known type's payload is shorter than the documented minimum.
func TestDecode_ShortPayloadWarning(t *testing.T) {
	// NearbyInfo (0x10) wants ≥5 value bytes; give it 2.
	got, err := Decode("1002 AA BB")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	tlv := got.TLVs[0]
	if tlv.DecodeWarning == "" {
		t.Error("expected DecodeWarning for short NearbyInfo")
	}
	if !strings.Contains(tlv.DecodeWarning, "NearbyInfo") {
		t.Errorf("warning = %q; want to mention NearbyInfo", tlv.DecodeWarning)
	}
	if tlv.Fields != nil {
		t.Error("Fields should be nil when DecodeWarning is set")
	}
}

// TestDecode_TruncatedTLV — an L byte that overruns the buffer.
// The walker should report the offset and the size mismatch.
func TestDecode_TruncatedTLV(t *testing.T) {
	// Type 0x10, claims length 5, only 2 value bytes present.
	_, err := Decode("1005 AA BB")
	if err == nil {
		t.Fatal("want error for truncated TLV, got nil")
	}
	if !strings.Contains(err.Error(), "offset 0") {
		t.Errorf("error = %q; want it to mention offset 0", err.Error())
	}
}

// TestDecode_MissingLengthByte — a type byte at end-of-buffer with
// no length byte following.
func TestDecode_MissingLengthByte(t *testing.T) {
	_, err := Decode("10")
	if err == nil {
		t.Fatal("want error for missing length byte")
	}
	if !strings.Contains(err.Error(), "missing length") {
		t.Errorf("error = %q; want 'missing length'", err.Error())
	}
}

// TestDecode_Empty returns a hard error on whitespace-only or empty
// input.
func TestDecode_Empty(t *testing.T) {
	for _, in := range []string{"", "  ", "\n\t"} {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("Decode(%q) = nil error; want error", in)
		}
	}
}

// TestDecode_InvalidHex rejects non-hex input cleanly.
func TestDecode_InvalidHex(t *testing.T) {
	_, err := Decode("10ZZ")
	if err == nil {
		t.Fatal("want error for invalid hex")
	}
	if !strings.Contains(err.Error(), "invalid hex") {
		t.Errorf("error = %q; want 'invalid hex'", err.Error())
	}
}

// TestDecode_IBeacon parses an iBeacon payload — verifies 16-byte
// UUID + major/minor + TX power decoding.
func TestDecode_IBeacon(t *testing.T) {
	// type=0x02, length=21, UUID 0123...FF, major=0x1234, minor=0x5678, tx=-59
	got, err := Decode("0215000102030405060708090A0B0C0D0E0F1234 5678 C5")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	tlv := got.TLVs[0]
	if tlv.Name != "iBeacon" {
		t.Errorf("Name = %q", tlv.Name)
	}
	if tlv.Fields["proximity_uuid"] != "000102030405060708090A0B0C0D0E0F" {
		t.Errorf("proximity_uuid = %v", tlv.Fields["proximity_uuid"])
	}
	if tlv.Fields["major"] != 0x1234 {
		t.Errorf("major = %v; want 0x1234", tlv.Fields["major"])
	}
	if tlv.Fields["minor"] != 0x5678 {
		t.Errorf("minor = %v; want 0x5678", tlv.Fields["minor"])
	}
	if tlv.Fields["tx_power_dbm"] != int8(-59) {
		t.Errorf("tx_power_dbm = %v (%T); want -59", tlv.Fields["tx_power_dbm"], tlv.Fields["tx_power_dbm"])
	}
}
