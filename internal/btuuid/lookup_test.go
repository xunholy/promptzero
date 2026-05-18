package btuuid

import (
	"testing"
)

// TestLookup_BatteryService pins the canonical Battery service
// 16-bit UUID 0x180F.
func TestLookup_BatteryService(t *testing.T) {
	got, err := Lookup("180F")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Name != "Battery" {
		t.Errorf("Name = %q; want 'Battery'", got.Name)
	}
	if got.Category != "Service" {
		t.Errorf("Category = %q; want 'Service'", got.Category)
	}
	if got.ShortUUID != "180F" {
		t.Errorf("ShortUUID = %q", got.ShortUUID)
	}
	if got.CanonicalUUID != "0000180F-0000-1000-8000-00805F9B34FB" {
		t.Errorf("CanonicalUUID = %q", got.CanonicalUUID)
	}
}

// TestLookup_DeviceNameCharacteristic pins a common
// characteristic (0x2A00 Device Name).
func TestLookup_DeviceNameCharacteristic(t *testing.T) {
	got, err := Lookup("2A00")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Name != "Device Name" {
		t.Errorf("Name = %q", got.Name)
	}
	if got.Category != "Characteristic" {
		t.Errorf("Category = %q; want 'Characteristic'", got.Category)
	}
}

// TestLookup_CCCDDescriptor pins the Client Characteristic
// Configuration Descriptor (0x2902 — the most common
// descriptor operators encounter when subscribing to
// notifications).
func TestLookup_CCCDDescriptor(t *testing.T) {
	got, err := Lookup("2902")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Name != "Client Characteristic Configuration" {
		t.Errorf("Name = %q", got.Name)
	}
	if got.Category != "Descriptor" {
		t.Errorf("Category = %q; want 'Descriptor'", got.Category)
	}
}

// TestLookup_EddystoneServiceFEAA pins the proprietary
// Eddystone UUID 0xFEAA (in the 0xFEXX range, not the
// canonical 0x18xx Services range).
func TestLookup_EddystoneServiceFEAA(t *testing.T) {
	got, err := Lookup("FEAA")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Name != "Eddystone (Google)" {
		t.Errorf("Name = %q", got.Name)
	}
	if got.Category != "Service" {
		t.Errorf("Category = %q", got.Category)
	}
}

// TestLookup_128BitSIGBase exercises the 128-bit base-pattern
// detection. Input matches the SIG base UUID with 0x180F in
// the short slot.
func TestLookup_128BitSIGBase(t *testing.T) {
	got, err := Lookup("0000180F-0000-1000-8000-00805F9B34FB")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.ShortUUID != "180F" {
		t.Errorf("ShortUUID = %q; want '180F' (extracted from 128-bit)", got.ShortUUID)
	}
	if got.Name != "Battery" {
		t.Errorf("Name = %q", got.Name)
	}
	if got.VendorSpecific {
		t.Error("VendorSpecific should be false for base-pattern UUID")
	}
}

// TestLookup_128BitUnhyphenated accepts the 32-char form
// without separators.
func TestLookup_128BitUnhyphenated(t *testing.T) {
	got, err := Lookup("0000180F00001000800000805F9B34FB")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.ShortUUID != "180F" {
		t.Errorf("ShortUUID = %q", got.ShortUUID)
	}
	if got.Name != "Battery" {
		t.Errorf("Name = %q", got.Name)
	}
}

// TestLookup_128BitVendorSpecific exercises a vendor-allocated
// random 128-bit UUID — should be flagged as VendorSpecific
// with no name lookup.
func TestLookup_128BitVendorSpecific(t *testing.T) {
	got, err := Lookup("6E400001-B5A3-F393-E0A9-E50E24DCCA9E") // Nordic UART Service
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !got.VendorSpecific {
		t.Error("VendorSpecific should be true for non-base-pattern UUID")
	}
	if got.ShortUUID != "" {
		t.Errorf("ShortUUID = %q; want empty for vendor UUID", got.ShortUUID)
	}
	if got.Name != "" {
		t.Errorf("Name = %q; want empty for vendor UUID", got.Name)
	}
}

// TestLookup_UnknownShortUUID — 16-bit UUID not in our catalog
// still resolves structurally (no Name, no Category).
func TestLookup_UnknownShortUUID(t *testing.T) {
	got, err := Lookup("ABCD")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.ShortUUID != "ABCD" {
		t.Errorf("ShortUUID = %q", got.ShortUUID)
	}
	if got.Name != "" {
		t.Errorf("Name = %q; want empty", got.Name)
	}
	if got.Category != "" {
		t.Errorf("Category = %q; want empty", got.Category)
	}
	if got.CanonicalUUID != "0000ABCD-0000-1000-8000-00805F9B34FB" {
		t.Errorf("CanonicalUUID = %q", got.CanonicalUUID)
	}
}

// TestLookup_0xPrefix accepts the 0x hex prefix.
func TestLookup_0xPrefix(t *testing.T) {
	got, err := Lookup("0x180F")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Name != "Battery" {
		t.Errorf("Name = %q", got.Name)
	}
}

// TestLookup_CaseInsensitive — lowercase input should normalise
// to uppercase for the table lookup.
func TestLookup_CaseInsensitive(t *testing.T) {
	got, err := Lookup("180f")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Name != "Battery" {
		t.Errorf("Name = %q", got.Name)
	}
}

// TestLookup_Separators — ':' / '-' / '_' / whitespace tolerated.
func TestLookup_Separators(t *testing.T) {
	cases := []string{
		"18:0F",
		"18-0F",
		"18_0F",
		" 180 F ",
	}
	for _, in := range cases {
		got, err := Lookup(in)
		if err != nil {
			t.Errorf("Lookup(%q): %v", in, err)
			continue
		}
		if got.Name != "Battery" {
			t.Errorf("Lookup(%q): Name = %q", in, got.Name)
		}
	}
}

// TestLookup_InvalidInput — empty / wrong length / non-hex.
func TestLookup_InvalidInput(t *testing.T) {
	if _, err := Lookup(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Lookup("ABC"); err == nil {
		t.Error("3-char input: want error (not 4 or 32)")
	}
	if _, err := Lookup("ZZZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestLookup_SpotChecks pins a handful of well-known UUIDs
// across all 3 categories.
func TestLookup_SpotChecks(t *testing.T) {
	cases := []struct {
		uuid     string
		name     string
		category string
	}{
		// Services
		{"1800", "Generic Access", "Service"},
		{"180A", "Device Information", "Service"},
		{"180D", "Heart Rate", "Service"},
		{"180F", "Battery", "Service"},
		{"1812", "Human Interface Device", "Service"},
		{"FEAA", "Eddystone (Google)", "Service"},
		{"FD6F", "Exposure Notification (COVID-19)", "Service"},
		// Characteristics
		{"2A00", "Device Name", "Characteristic"},
		{"2A19", "Battery Level", "Characteristic"},
		{"2A29", "Manufacturer Name String", "Characteristic"},
		{"2A37", "Heart Rate Measurement", "Characteristic"},
		{"2A6E", "Temperature", "Characteristic"},
		// Descriptors
		{"2900", "Characteristic Extended Properties", "Descriptor"},
		{"2902", "Client Characteristic Configuration", "Descriptor"},
		{"2904", "Characteristic Presentation Format", "Descriptor"},
	}
	for _, c := range cases {
		got, err := Lookup(c.uuid)
		if err != nil {
			t.Errorf("Lookup(%q): %v", c.uuid, err)
			continue
		}
		if got.Name != c.name {
			t.Errorf("Lookup(%q): Name = %q; want %q", c.uuid, got.Name, c.name)
		}
		if got.Category != c.category {
			t.Errorf("Lookup(%q): Category = %q; want %q", c.uuid, got.Category, c.category)
		}
	}
}
