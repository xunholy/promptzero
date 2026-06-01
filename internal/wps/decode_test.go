// SPDX-License-Identifier: AGPL-3.0-or-later

package wps

import (
	"strings"
	"testing"
)

// wscStream is a hand-built WSC attribute stream exercising the
// recon-relevant attributes:
//
//	Version 1.0 / State Configured / AP Setup Locked / Device Password ID
//	0x0000 (Default PIN) / Config Methods 0x0084 (Label + Push Button) /
//	Device Name "MyAP" / Manufacturer "Vendor" / UUID-E (16 bytes) /
//	an unknown attribute 0x9999.
const wscStream = "104A000110" + // Version = 0x10 -> 1.0
	"1044000102" + // Setup State = Configured
	"1057000101" + // AP Setup Locked = true
	"101200020000" + // Device Password ID = 0x0000 (Default PIN)
	"100800020084" + // Config Methods = 0x0084 (Label | Push Button)
	"101100044D794150" + // Device Name = "MyAP"
	"1021000656656E646F72" + // Manufacturer = "Vendor"
	"1047001000112233445566778899AABBCCDDEEFF" + // UUID-E
	"99990002ABCD" // unknown attribute

func TestDecode_KnownAttributes(t *testing.T) {
	w, err := Decode(wscStream)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if w.Version != "1.0" {
		t.Errorf("version = %q, want 1.0", w.Version)
	}
	if w.SetupState != "Configured" {
		t.Errorf("setup_state = %q, want Configured", w.SetupState)
	}
	if w.APSetupLocked == nil || !*w.APSetupLocked {
		t.Errorf("ap_setup_locked = %v, want true", w.APSetupLocked)
	}
	if w.DevicePasswordID != "Default (PIN)" {
		t.Errorf("device_password_id = %q, want 'Default (PIN)'", w.DevicePasswordID)
	}
	if w.DeviceName != "MyAP" {
		t.Errorf("device_name = %q, want MyAP", w.DeviceName)
	}
	if w.Manufacturer != "Vendor" {
		t.Errorf("manufacturer = %q, want Vendor", w.Manufacturer)
	}
	if w.Count != 9 {
		t.Errorf("count = %d, want 9", w.Count)
	}
}

func TestDecode_ConfigMethods(t *testing.T) {
	w, err := Decode(wscStream)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var methods []string
	for _, a := range w.Attributes {
		if a.Type == attrConfigMethods {
			if m, ok := a.Decoded.([]string); ok {
				methods = m
			}
		}
	}
	got := strings.Join(methods, ",")
	if got != "Label,Push Button" {
		t.Errorf("config methods = %q, want 'Label,Push Button'", got)
	}
}

func TestDecode_UnknownAttributeSurfaced(t *testing.T) {
	w, err := Decode(wscStream)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	last := w.Attributes[len(w.Attributes)-1]
	if last.Type != 0x9999 {
		t.Fatalf("last attr type = 0x%04X, want 0x9999", last.Type)
	}
	if last.Name != "Unknown" {
		t.Errorf("unknown attr name = %q, want Unknown", last.Name)
	}
	if last.Decoded != nil {
		t.Errorf("unknown attr decoded = %v, want nil", last.Decoded)
	}
	if last.ValueHex != "ABCD" {
		t.Errorf("unknown attr value_hex = %q, want ABCD", last.ValueHex)
	}
}

func TestDecode_PrefixStripping(t *testing.T) {
	// OUI+type prefix (00 50 F2 04) and full vendor IE (DD <len> ...).
	bare := "104A000110"
	ouiType := "0050F204" + bare
	// full IE: DD <len> 00 50 F2 04 <wsc>; len = 4 (oui+type) + 5 (wsc) = 9 = 0x09
	fullIE := "DD09" + "0050F204" + bare
	for name, in := range map[string]string{"oui_type": ouiType, "full_ie": fullIE} {
		w, err := Decode(in)
		if err != nil {
			t.Fatalf("Decode(%s): %v", name, err)
		}
		if w.Version != "1.0" {
			t.Errorf("%s: version = %q, want 1.0", name, w.Version)
		}
	}
}

func TestDecode_TruncatedTLV(t *testing.T) {
	// Version OK, then an attribute claiming 16 bytes with only 2 present.
	w, err := Decode("104A000110" + "10470010ABCD")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if w.Version != "1.0" {
		t.Errorf("version = %q, want 1.0 (first attr should parse)", w.Version)
	}
	if len(w.Notes) == 0 {
		t.Error("expected a note about the truncated attribute")
	}
}

func TestDecode_APSetupLockedFalse(t *testing.T) {
	w, err := Decode("1057000100") // AP Setup Locked = 0 (not locked)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if w.APSetupLocked == nil || *w.APSetupLocked {
		t.Errorf("ap_setup_locked = %v, want false", w.APSetupLocked)
	}
}

func TestDecode_Errors(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("expected error for empty input")
	}
	if _, err := Decode("zzzz"); err == nil {
		t.Error("expected error for non-hex input")
	}
}
