package ble

import (
	"strings"
	"testing"
)

// TestDecodeEddystone_UID parses the canonical Eddystone-UID
// payload from google/eddystone's worked example:
//
//	type=0x00, tx_power=0xEE (-18 dBm), namespace 10 bytes,
//	  instance 6 bytes, 2 reserved bytes.
func TestDecodeEddystone_UID(t *testing.T) {
	// tx=0xEE, namespace=01..0A, instance=11..16, reserved=0000
	got, err := DecodeEddystone("00 EE 01 02 03 04 05 06 07 08 09 0A 11 12 13 14 15 16 00 00")
	if err != nil {
		t.Fatalf("DecodeEddystone: %v", err)
	}
	if got.FrameName != "UID" {
		t.Errorf("FrameName = %q; want 'UID'", got.FrameName)
	}
	if got.Fields["tx_power_dbm"] != -18 {
		t.Errorf("tx_power_dbm = %v; want -18", got.Fields["tx_power_dbm"])
	}
	if got.Fields["namespace"] != "0102030405060708090A" {
		t.Errorf("namespace = %v", got.Fields["namespace"])
	}
	if got.Fields["instance"] != "111213141516" {
		t.Errorf("instance = %v", got.Fields["instance"])
	}
}

// TestDecodeEddystone_URL_GoogleCom encodes the worked-example
// from google/eddystone-url for "https://www.google.com" — scheme
// byte 0x01, then "google" + 0x07 (".com").
func TestDecodeEddystone_URL_GoogleCom(t *testing.T) {
	// type=0x10, tx=0x20 (32 dBm), scheme=0x01, "google"=67 6F 6F 67 6C 65, ".com"=07
	got, err := DecodeEddystone("10 20 01 67 6F 6F 67 6C 65 07")
	if err != nil {
		t.Fatalf("DecodeEddystone: %v", err)
	}
	if got.FrameName != "URL" {
		t.Errorf("FrameName = %q; want 'URL'", got.FrameName)
	}
	if got.Fields["url"] != "https://www.google.com" {
		t.Errorf("url = %q; want 'https://www.google.com'", got.Fields["url"])
	}
	if got.Fields["scheme_name"] != "https://www." {
		t.Errorf("scheme_name = %v", got.Fields["scheme_name"])
	}
	if got.Fields["tx_power_dbm"] != 32 {
		t.Errorf("tx_power_dbm = %v; want 32", got.Fields["tx_power_dbm"])
	}
}

// TestDecodeEddystone_URL_HTTP_NoExpansion tests the plain
// "http://" scheme byte with a URL that has no TLD-expansion
// bytes — just ASCII path bytes.
func TestDecodeEddystone_URL_HTTP_NoExpansion(t *testing.T) {
	// type=0x10, tx=0x00, scheme=0x02 (http://), "example.io"
	// Encoded bytes: 65 78 61 6D 70 6C 65 2E 69 6F
	got, err := DecodeEddystone("10 00 02 65 78 61 6D 70 6C 65 2E 69 6F")
	if err != nil {
		t.Fatalf("DecodeEddystone: %v", err)
	}
	if got.Fields["url"] != "http://example.io" {
		t.Errorf("url = %q; want 'http://example.io'", got.Fields["url"])
	}
}

// TestDecodeEddystone_URL_ReservedByteWarns surfaces a reserved
// byte (0x0E-0x20, 0x7F-0xFF) in a reserved_bytes list rather
// than silently dropping or appending it.
func TestDecodeEddystone_URL_ReservedByteWarns(t *testing.T) {
	// type=0x10, tx=0, scheme=3 (https://), then 'a' + 0x0E (reserved)
	got, err := DecodeEddystone("10 00 03 61 0E")
	if err != nil {
		t.Fatalf("DecodeEddystone: %v", err)
	}
	if got.Fields["url"] != "https://a" {
		t.Errorf("url = %q; want 'https://a'", got.Fields["url"])
	}
	r, ok := got.Fields["reserved_bytes"].([]string)
	if !ok || len(r) != 1 {
		t.Fatalf("reserved_bytes = %v (type %T); want one entry", got.Fields["reserved_bytes"], got.Fields["reserved_bytes"])
	}
	if !strings.Contains(r[0], "0x0E") {
		t.Errorf("reserved entry = %q; want it to mention 0x0E", r[0])
	}
}

// TestDecodeEddystone_URL_BadScheme returns a warning when the
// scheme byte is outside 0x00-0x03.
func TestDecodeEddystone_URL_BadScheme(t *testing.T) {
	got, err := DecodeEddystone("10 00 04 6F 6B")
	if err != nil {
		t.Fatalf("DecodeEddystone: %v", err)
	}
	if got.DecodeWarning == "" {
		t.Error("want DecodeWarning for invalid scheme byte")
	}
	if !strings.Contains(got.DecodeWarning, "scheme") {
		t.Errorf("warning = %q; want to mention 'scheme'", got.DecodeWarning)
	}
}

// TestDecodeEddystone_TLM parses a TLM frame: version 0x00,
// battery 3000 mV, temperature 25.5°C (0x1980 = 6528 raw,
// 6528/256 = 25.5), adv_count 0x00010000, sec*100ms 0x00000064.
func TestDecodeEddystone_TLM(t *testing.T) {
	// type=0x20, version=0x00, battery=0x0BB8 (3000 mV),
	// temp=0x1980, count=0x00010000, sec*100ms=0x00000064 (10s)
	got, err := DecodeEddystone("20 00 0B B8 19 80 00 01 00 00 00 00 00 64")
	if err != nil {
		t.Fatalf("DecodeEddystone: %v", err)
	}
	if got.FrameName != "TLM" {
		t.Errorf("FrameName = %q; want 'TLM'", got.FrameName)
	}
	if got.Fields["version"] != 0 {
		t.Errorf("version = %v; want 0", got.Fields["version"])
	}
	if got.Fields["battery_mv"] != 3000 {
		t.Errorf("battery_mv = %v; want 3000", got.Fields["battery_mv"])
	}
	if got.Fields["temperature_c"] != 25.5 {
		t.Errorf("temperature_c = %v; want 25.5", got.Fields["temperature_c"])
	}
	if got.Fields["adv_count"] != 0x10000 {
		t.Errorf("adv_count = %v; want %d", got.Fields["adv_count"], 0x10000)
	}
	if got.Fields["uptime_seconds"] != 10.0 {
		t.Errorf("uptime_seconds = %v; want 10.0", got.Fields["uptime_seconds"])
	}
}

// TestDecodeEddystone_TLM_Encrypted recognises version 0x01 (eTLM)
// without trying to dissect the encrypted body.
func TestDecodeEddystone_TLM_Encrypted(t *testing.T) {
	// type=0x20, version=0x01, then 12 bytes of "encrypted" body
	got, err := DecodeEddystone("20 01 00112233445566778899AABB CCDD")
	if err != nil {
		t.Fatalf("DecodeEddystone: %v", err)
	}
	if got.Fields["version_name"] != "eTLM (encrypted)" {
		t.Errorf("version_name = %v", got.Fields["version_name"])
	}
	if got.Fields["encrypted_body"] == nil {
		t.Errorf("encrypted_body missing")
	}
}

// TestDecodeEddystone_EID parses an EID frame: tx_power + 8-byte
// ephemeral ID.
func TestDecodeEddystone_EID(t *testing.T) {
	got, err := DecodeEddystone("30 F0 0102030405060708")
	if err != nil {
		t.Fatalf("DecodeEddystone: %v", err)
	}
	if got.FrameName != "EID" {
		t.Errorf("FrameName = %q; want 'EID'", got.FrameName)
	}
	if got.Fields["tx_power_dbm"] != -16 {
		t.Errorf("tx_power_dbm = %v; want -16", got.Fields["tx_power_dbm"])
	}
	if got.Fields["ephemeral_id"] != "0102030405060708" {
		t.Errorf("ephemeral_id = %v", got.Fields["ephemeral_id"])
	}
}

// TestDecodeEddystone_UUIDPrefix accepts the 0xAA 0xFE service-
// UUID prefix.
func TestDecodeEddystone_UUIDPrefix(t *testing.T) {
	got, err := DecodeEddystone("AA FE 10 20 01 67 6F 6F 67 6C 65 07")
	if err != nil {
		t.Fatalf("DecodeEddystone: %v", err)
	}
	if got.FrameName != "URL" || got.Fields["url"] != "https://www.google.com" {
		t.Errorf("decode wrong: %+v", got)
	}
}

// TestDecodeEddystone_FullADStructure accepts the full
// <len> 16 AA FE <payload> AD-structure wrapper.
func TestDecodeEddystone_FullADStructure(t *testing.T) {
	// 0x0D = length-of-rest (1 type + 2 UUID + 10 payload = 13).
	// Payload = URL frame "https://www.google.com" (10 bytes).
	got, err := DecodeEddystone("0D 16 AA FE 10 20 01 67 6F 6F 67 6C 65 07")
	if err != nil {
		t.Fatalf("DecodeEddystone: %v", err)
	}
	if got.FrameName != "URL" || got.Fields["url"] != "https://www.google.com" {
		t.Errorf("decode wrong: %+v", got)
	}
}

// TestDecodeEddystone_UnknownFrameType — out-of-catalog frame
// type still gets walked with FrameName="Unknown" and raw hex.
func TestDecodeEddystone_UnknownFrameType(t *testing.T) {
	got, err := DecodeEddystone("FF AA BB CC")
	if err != nil {
		t.Fatalf("DecodeEddystone: %v", err)
	}
	if got.FrameName != "Unknown" {
		t.Errorf("FrameName = %q; want 'Unknown'", got.FrameName)
	}
	if got.Hex != "FFAABBCC" {
		t.Errorf("Hex = %q", got.Hex)
	}
	if got.Fields != nil {
		t.Errorf("Fields should be nil for unknown frame, got %v", got.Fields)
	}
}

// TestDecodeEddystone_ShortPayloadWarn surfaces a DecodeWarning
// when a known frame type's body is shorter than the documented
// minimum.
func TestDecodeEddystone_ShortPayloadWarn(t *testing.T) {
	// UID (0x00) wants ≥17 body bytes; give it 4.
	got, err := DecodeEddystone("00 EE 01 02 03")
	if err != nil {
		t.Fatalf("DecodeEddystone: %v", err)
	}
	if got.DecodeWarning == "" {
		t.Error("expected DecodeWarning for short UID")
	}
	if got.Fields != nil {
		t.Error("Fields should be nil when DecodeWarning is set")
	}
}

// TestDecodeEddystone_Empty and Invalid hex are rejected with
// operator-facing errors.
func TestDecodeEddystone_BadInput(t *testing.T) {
	if _, err := DecodeEddystone(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := DecodeEddystone("ZZZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecodeEddystone_ToleratesSeparators — '_', '-', ':',
// whitespace all stripped.
func TestDecodeEddystone_ToleratesSeparators(t *testing.T) {
	for _, in := range []string{
		"10:20:01:67:6F:6F:67:6C:65:07",
		"10-20-01-67-6F-6F-67-6C-65-07",
		"10_20_01_67_6F_6F_67_6C_65_07",
		"  10 20 01 67 6F 6F 67 6C 65 07  ",
	} {
		got, err := DecodeEddystone(in)
		if err != nil {
			t.Errorf("DecodeEddystone(%q): %v", in, err)
			continue
		}
		if got.Fields["url"] != "https://www.google.com" {
			t.Errorf("DecodeEddystone(%q): url = %v", in, got.Fields["url"])
		}
	}
}
