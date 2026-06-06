// SPDX-License-Identifier: AGPL-3.0-or-later

package homeplugav

import (
	"strings"
	"testing"
)

// The version + MMTYPE (little-endian) were verified against scapy's
// HomePlugAV layer (scapy.contrib.homeplugav): e.g. version 0, MMTYPE
// 0xA050 -> wire bytes "00 50A0 ..." (00 + LE 50 a0).

func TestDecodeSetEncryptionKey(t *testing.T) {
	// version 1.0, MMTYPE 0xA050 (Set Encryption Key Request), OUI 00b052 + body.
	const v = "0050a000b052" + "aabbccddeeff"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 0 || r.VersionName != "1.0" {
		t.Fatalf("version = %d/%q", r.Version, r.VersionName)
	}
	if r.MMType != 0xA050 || r.MMTypeName != "Set Encryption Key Request" {
		t.Errorf("mmtype = %#x/%q", r.MMType, r.MMTypeName)
	}
	if r.SubType != "Request" {
		t.Errorf("subtype = %q", r.SubType)
	}
	if r.Category != "Manufacturer-Specific (vendor) MME" {
		t.Errorf("category = %q", r.Category)
	}
	if r.BodyHex != "00B052AABBCCDDEEFF" {
		t.Errorf("body = %q", r.BodyHex)
	}
	// Set-Encryption-Key should warn about the NMK.
	var nmk bool
	for _, n := range r.Notes {
		if strings.Contains(n, "Network Membership Key") {
			nmk = true
		}
	}
	if !nmk {
		t.Error("expected NMK warning for Set Encryption Key")
	}
}

func TestDecodeNetworkInfoConfirmation(t *testing.T) {
	// version 1.0, MMTYPE 0xA039 (Network Information Confirmation).
	const v = "0039a0" + "00b052" + "010203"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MMType != 0xA039 || r.MMTypeName != "Network Information Confirmation" {
		t.Errorf("mmtype = %#x/%q", r.MMType, r.MMTypeName)
	}
	if r.SubType != "Confirmation" {
		t.Errorf("subtype = %q, want Confirmation", r.SubType)
	}
}

func TestDecodeSnifferRequest(t *testing.T) {
	// MMTYPE 0xA034 (Sniffer Request) — should warn about powerline sniffing.
	const v = "0034a000b052"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MMTypeName != "Sniffer Request" {
		t.Fatalf("mmtype = %q", r.MMTypeName)
	}
	var warn bool
	for _, n := range r.Notes {
		if strings.Contains(n, "sniffing") {
			warn = true
		}
	}
	if !warn {
		t.Error("expected sniffer warning")
	}
}

func TestDecodeV11(t *testing.T) {
	// version 1.1 (0x01).
	const v = "011ca0000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 1 || r.VersionName != "1.1" {
		t.Errorf("version = %d/%q", r.Version, r.VersionName)
	}
	if r.MMType != 0xA01C || r.MMTypeName != "Reset Device Request" {
		t.Errorf("mmtype = %#x/%q", r.MMType, r.MMTypeName)
	}
}

func TestDecodeUnknownMMType(t *testing.T) {
	// An MMTYPE not in the table -> hex name, still classified by range.
	const v = "00ffff"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MMTypeName != "0xFFFF" || r.Category != "Vendor-Specific MME" {
		t.Errorf("unknown mmtype = %q/%q", r.MMTypeName, r.Category)
	}
}

func TestDecodeRejects(t *testing.T) {
	if _, err := Decode("0250a0"); err == nil {
		t.Fatal("expected rejection of version 2")
	}
	if _, err := Decode("0050"); err == nil {
		t.Fatal("expected error on short header")
	}
}
