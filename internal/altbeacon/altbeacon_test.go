// SPDX-License-Identifier: AGPL-3.0-or-later

package altbeacon

import (
	"encoding/hex"
	"strings"
	"testing"
)

// specExampleAD is the canonical worked example from the AltBeacon spec
// (github.com/AltBeacon/spec): company 0x0118 (Radius Networks), beacon
// code BE AC, beacon ID 2F234454...0002, reference RSSI 0xC5 (-59), mfg
// reserved 0x00, as a full advertising-data record.
const (
	specExampleAD = "1BFF1801BEAC2F234454CF6D4A0FADF2F4911BA9FFA600010002C500"
	specBeaconID  = "2F234454CF6D4A0FADF2F4911BA9FFA600010002"
	specMfgData   = "1801BEAC2F234454CF6D4A0FADF2F4911BA9FFA600010002C500"
)

// TestDecode_SpecExample anchors the decoder against the spec worked example.
func TestDecode_SpecExample(t *testing.T) {
	d, err := Decode(specExampleAD)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.OuterFormat != "ad_record" {
		t.Errorf("outer_format = %s, want ad_record", d.OuterFormat)
	}
	if d.MfgID != 0x0118 {
		t.Errorf("mfg_id = 0x%04X, want 0x0118", d.MfgID)
	}
	if d.BeaconID != specBeaconID {
		t.Errorf("beacon_id = %s, want %s", d.BeaconID, specBeaconID)
	}
	if d.RefRSSI != -59 {
		t.Errorf("ref_rssi = %d, want -59", d.RefRSSI)
	}
	if d.MfgReserved != 0 {
		t.Errorf("mfg_reserved = %d, want 0", d.MfgReserved)
	}
	if d.CommonUUID != "2F234454-CF6D-4A0F-ADF2-F4911BA9FFA6" {
		t.Errorf("common_uuid = %s", d.CommonUUID)
	}
	if d.CommonMajor != 1 || d.CommonMinor != 2 {
		t.Errorf("common major/minor = %d/%d, want 1/2", d.CommonMajor, d.CommonMinor)
	}
}

// TestDecode_Framings confirms all three input framings decode equivalently.
func TestDecode_Framings(t *testing.T) {
	beaconCodeOnly := "BEAC2F234454CF6D4A0FADF2F4911BA9FFA600010002C500"
	for name, in := range map[string]string{
		"ad_record":         specExampleAD,
		"manufacturer_data": specMfgData,
		"beacon_code":       beaconCodeOnly,
	} {
		d, err := Decode(in)
		if err != nil {
			t.Fatalf("Decode(%s): %v", name, err)
		}
		if d.OuterFormat != name {
			t.Errorf("%s: outer_format = %s", name, d.OuterFormat)
		}
		if d.BeaconID != specBeaconID {
			t.Errorf("%s: beacon_id = %s", name, d.BeaconID)
		}
	}
}

// TestEncode_SpecExample hand-verifies the encoder produces the spec
// example's manufacturer-data and AD-record bytes exactly.
func TestEncode_SpecExample(t *testing.T) {
	mfg, err := Encode(EncodeRequest{MfgID: 0x0118, BeaconID: specBeaconID, RefRSSI: -59, MfgReserved: 0})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if got := strings.ToUpper(hex.EncodeToString(mfg)); got != specMfgData {
		t.Errorf("manufacturer data = %s, want %s", got, specMfgData)
	}
	ad, err := Encode(EncodeRequest{MfgID: 0x0118, BeaconID: specBeaconID, RefRSSI: -59, MfgReserved: 0, Wrap: "ad"})
	if err != nil {
		t.Fatalf("Encode(ad): %v", err)
	}
	if got := strings.ToUpper(hex.EncodeToString(ad)); got != specExampleAD {
		t.Errorf("ad record = %s, want %s", got, specExampleAD)
	}
}

// TestRoundTrip confirms Encode → Decode recovers every field.
func TestRoundTrip(t *testing.T) {
	b, err := Encode(EncodeRequest{
		MfgID: 0x004C, BeaconID: "0123456789ABCDEF0123456789ABCDEF00010002", RefRSSI: -70, MfgReserved: 0x42, Wrap: "ad",
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	d, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if d.MfgID != 0x004C || d.RefRSSI != -70 || d.MfgReserved != 0x42 {
		t.Errorf("round-trip mismatch: %+v", d)
	}
	if d.BeaconID != "0123456789ABCDEF0123456789ABCDEF00010002" {
		t.Errorf("beacon_id round-trips to %s", d.BeaconID)
	}
}

// TestEncode_DefaultMfgID confirms a zero MfgID falls back to 0x0118.
func TestEncode_DefaultMfgID(t *testing.T) {
	b, err := Encode(EncodeRequest{BeaconID: specBeaconID, RefRSSI: -59})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	d, _ := Decode(hex.EncodeToString(b))
	if d.MfgID != DefaultMfgID {
		t.Errorf("default mfg_id = 0x%04X, want 0x0118", d.MfgID)
	}
}

func TestDecode_Errors(t *testing.T) {
	bad := []string{
		"",                                    // empty
		"DEADBEEF",                            // no BEAC code
		"1801BEAC2F234454",                    // too short
		"1801CAFE" + strings.Repeat("00", 22), // wrong beacon code
	}
	for _, in := range bad {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q): expected error", in)
		}
	}
}

func TestEncode_Errors(t *testing.T) {
	bad := []EncodeRequest{
		{BeaconID: "0011"},                         // short beacon ID
		{BeaconID: "nothex"},                       // bad hex
		{BeaconID: specBeaconID, MfgReserved: 999}, // reserved out of range
		{BeaconID: specBeaconID, Wrap: "bogus"},    // bad wrap
	}
	for i, r := range bad {
		if _, err := Encode(r); err == nil {
			t.Errorf("case %d (%+v): expected error", i, r)
		}
	}
}
