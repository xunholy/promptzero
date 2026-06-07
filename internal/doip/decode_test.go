// SPDX-License-Identifier: AGPL-3.0-or-later

package doip

import "testing"

// Vectors are built from scapy.contrib.automotive.doip and verified
// field-for-field against ISO 13400.

func TestVehicleAnnouncement(t *testing.T) {
	r, err := Decode("02fd0004000000215756575a5a5a314a5a58573030303030310e80010203040506aabbccddeeff1000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProtocolVersion != 2 || r.ProtocolVersionName != "ISO13400-2012" {
		t.Errorf("version = %d/%q", r.ProtocolVersion, r.ProtocolVersionName)
	}
	if !r.InverseVersionValid {
		t.Error("inverse version should be valid (0xFD == ~0x02)")
	}
	if r.PayloadTypeName != "Vehicle announcement / identification response" {
		t.Errorf("PayloadTypeName = %q", r.PayloadTypeName)
	}
	if r.VIN != "WVWZZZ1JZXW000001" {
		t.Errorf("VIN = %q", r.VIN)
	}
	if r.LogicalAddr != "0x0E80" {
		t.Errorf("LogicalAddr = %q", r.LogicalAddr)
	}
	if r.EID != "010203040506" {
		t.Errorf("EID = %q", r.EID)
	}
	if r.GID != "AABBCCDDEEFF" {
		t.Errorf("GID = %q", r.GID)
	}
	if r.VINGIDStatus != "VIN and/or GID are synchronized" {
		t.Errorf("VINGIDStatus = %q", r.VINGIDStatus)
	}
}

func TestRoutingActivationRequest(t *testing.T) {
	r, err := Decode("02fd0005000000070e000000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.PayloadType != 0x0005 {
		t.Errorf("PayloadType = 0x%04X", r.PayloadType)
	}
	if r.SourceAddr != "0x0E00" {
		t.Errorf("SourceAddr = %q", r.SourceAddr)
	}
	if r.ActivationType != "Default" {
		t.Errorf("ActivationType = %q", r.ActivationType)
	}
}

func TestRoutingActivationResponseDeniedAuth(t *testing.T) {
	r, err := Decode("02fd0006000000090e000e800400000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.LogicalAddrTester != "0x0E00" || r.LogicalAddrEntity != "0x0E80" {
		t.Errorf("addrs = %q/%q", r.LogicalAddrTester, r.LogicalAddrEntity)
	}
	if r.RoutingActivationResp != "denied: missing authentication" {
		t.Errorf("RoutingActivationResp = %q", r.RoutingActivationResp)
	}
}

func TestDiagnosticMessageUDSPayload(t *testing.T) {
	r, err := Decode("02fd8001000000060e000e801003")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.PayloadTypeName != "Diagnostic message" {
		t.Errorf("PayloadTypeName = %q", r.PayloadTypeName)
	}
	if r.SourceAddr != "0x0E00" || r.TargetAddr != "0x0E80" {
		t.Errorf("addrs = %q/%q", r.SourceAddr, r.TargetAddr)
	}
	if r.UDSPayloadHex != "1003" {
		t.Errorf("UDSPayloadHex = %q, want 1003 (UDS DiagnosticSessionControl)", r.UDSPayloadHex)
	}
}

func TestGenericNACK(t *testing.T) {
	r, err := Decode("02fd00000000000101")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.NACKCode != "Unknown payload type" {
		t.Errorf("NACKCode = %q", r.NACKCode)
	}
}

func TestDiagnosticMessageNACK(t *testing.T) {
	r, err := Decode("02fd8003000000050e000e8002")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.DiagNACKCode != "Invalid source address" {
		t.Errorf("DiagNACKCode = %q", r.DiagNACKCode)
	}
}

func TestInverseVersionInvalid(t *testing.T) {
	// inverse byte 0x00 (should be 0xFD for version 0x02) — flagged, still parsed.
	r, err := Decode("020000010000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.InverseVersionValid {
		t.Error("inverse version should be flagged invalid")
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "02fd00", "zz"} {
		// empty, < 8 bytes, non-hex
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
