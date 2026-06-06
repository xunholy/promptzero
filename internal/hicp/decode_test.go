// SPDX-License-Identifier: AGPL-3.0-or-later

package hicp

import (
	"strings"
	"testing"
)

// Vectors are the exact wire bytes produced by scapy's HICP layer
// (scapy.contrib.hicp); the Key=value parsing was verified against it.

func TestDecodeModuleScanResponse(t *testing.T) {
	const v = "Protocol version = 1.00;FB type = Anybus-S EtherNet/IP;Module version = 2.13;" +
		"MAC = 00:30:11:0a:0b:0c;IP = 192.168.1.50;SN = 255.255.255.0;GW = 192.168.1.1;" +
		"DHCP = OFF;PSWD = OFF;HN = abx-gw01;DNS1 = 8.8.8.8;DNS2 = 0.0.0.0;\x00"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageType != "module_scan_response" {
		t.Fatalf("type = %q", r.MessageType)
	}
	if r.FieldbusType != "Anybus-S EtherNet/IP" {
		t.Errorf("fieldbus = %q", r.FieldbusType)
	}
	if r.MACAddress != "00:30:11:0a:0b:0c" {
		t.Errorf("mac = %q", r.MACAddress)
	}
	if r.IPAddress != "192.168.1.50" || r.Hostname != "abx-gw01" {
		t.Errorf("ip/hn = %q/%q", r.IPAddress, r.Hostname)
	}
	if r.PasswordState != "OFF" {
		t.Errorf("pswd = %q", r.PasswordState)
	}
	// PSWD=OFF should produce the unauthenticated-reconfig warning.
	var warn bool
	for _, n := range r.Notes {
		if strings.Contains(n, "unauthenticated Configure") {
			warn = true
		}
	}
	if !warn {
		t.Error("expected unauthenticated-reconfig warning for PSWD=OFF")
	}
}

func TestDecodeModuleScan(t *testing.T) {
	const v = "MODULE SCAN\x00"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageType != "module_scan" {
		t.Errorf("type = %q, want module_scan", r.MessageType)
	}
}

func TestDecodeConfigure(t *testing.T) {
	// scapy emits the Configure target MAC with '-' separators.
	const v = "Configure: 00-30-11-0a-0b-0c;IP = 10.0.0.99;SN = 255.0.0.0;GW = 10.0.0.1;" +
		"DHCP = OFF;HN = pwned;DNS1 = 0.0.0.0;DNS2 = 0.0.0.0;\x00"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageType != "configure" {
		t.Fatalf("type = %q", r.MessageType)
	}
	if r.TargetMAC != "00:30:11:0a:0b:0c" {
		t.Errorf("target mac = %q (want colon-normalised)", r.TargetMAC)
	}
	if r.IPAddress != "10.0.0.99" || r.Hostname != "pwned" {
		t.Errorf("new ip/hn = %q/%q", r.IPAddress, r.Hostname)
	}
}

func TestDecodeStatuses(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Reconfigured\x00", "reconfigured"},
		{"Invalid Configuration\x00", "invalid_configuration"},
		{"Invalid Password\x00", "invalid_password"},
		{"To: 00-30-11-0a-0b-0c", "wink"},
	} {
		r, err := Decode(tc.in)
		if err != nil {
			t.Fatalf("Decode(%q): %v", tc.in, err)
		}
		if r.MessageType != tc.want {
			t.Errorf("Decode(%q) type = %q, want %q", tc.in, r.MessageType, tc.want)
		}
	}
}

func TestDecodeHexInput(t *testing.T) {
	// "MODULE SCAN\x00" as hex.
	const v = "4d4f44554c45205343414e00"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageType != "module_scan" {
		t.Errorf("hex-input type = %q", r.MessageType)
	}
}

func TestDecodeRejectsJunk(t *testing.T) {
	if _, err := Decode("not a hicp message at all"); err == nil {
		t.Fatal("expected rejection of non-HICP text")
	}
	if _, err := Decode(""); err == nil {
		t.Fatal("expected error on empty input")
	}
}
