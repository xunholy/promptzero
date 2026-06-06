// SPDX-License-Identifier: AGPL-3.0-or-later

package roce

import "testing"

// Vectors are built from scapy.contrib.roce (BTH) and hand-verified
// bit-for-bit against the InfiniBand Architecture (IBA) BTH layout.

func TestRDMAReadRequest(t *testing.T) {
	// RC_RDMA_READ_REQUEST: pkey=0xFFFF dqpn=0x000123 ackreq=1 psn=0x000456
	r, err := Decode("0c00ffff0000012380000456")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "RC_RDMA_READ_REQUEST" {
		t.Errorf("OpcodeName = %q", r.OpcodeName)
	}
	if r.TransportService != "RC (Reliable Connection)" {
		t.Errorf("TransportService = %q", r.TransportService)
	}
	if r.PKey != "0xFFFF" {
		t.Errorf("PKey = %q", r.PKey)
	}
	if r.DestQP != "0x000123" {
		t.Errorf("DestQP = %q", r.DestQP)
	}
	if !r.AckReq {
		t.Error("AckReq should be true")
	}
	if r.PSN != 0x456 {
		t.Errorf("PSN = 0x%X, want 0x456", r.PSN)
	}
	if r.Solicited || r.MigReq || r.FECN || r.BECN || r.PadCount != 0 || r.HeaderVersion != 0 {
		t.Errorf("unexpected flags: %+v", r)
	}
}

func TestUDSendOnlyFlags(t *testing.T) {
	// UD_SEND_ONLY: solicited=1 padcount=2 pkey=0x8001 fecn=1 dqpn=0x00ABCD psn=0x00FF00
	r, err := Decode("64a080018000abcd0000ff00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "UD_SEND_ONLY" {
		t.Errorf("OpcodeName = %q", r.OpcodeName)
	}
	if r.TransportService != "UD (Unreliable Datagram)" {
		t.Errorf("TransportService = %q", r.TransportService)
	}
	if !r.Solicited {
		t.Error("Solicited should be true")
	}
	if r.PadCount != 2 {
		t.Errorf("PadCount = %d, want 2", r.PadCount)
	}
	if !r.FECN {
		t.Error("FECN should be true")
	}
	if r.BECN {
		t.Error("BECN should be false")
	}
	if r.PKey != "0x8001" {
		t.Errorf("PKey = %q", r.PKey)
	}
	if r.DestQP != "0x00ABCD" {
		t.Errorf("DestQP = %q", r.DestQP)
	}
	if r.PSN != 0xFF00 {
		t.Errorf("PSN = 0x%X", r.PSN)
	}
	if r.AckReq {
		t.Error("AckReq should be false")
	}
}

func TestCNP(t *testing.T) {
	r, err := Decode("8100ffff0000001000000000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "CNP" {
		t.Errorf("OpcodeName = %q", r.OpcodeName)
	}
	if r.TransportService != "CNP / Manufacturer-specific" {
		t.Errorf("TransportService = %q", r.TransportService)
	}
	foundCNP := false
	for _, n := range r.Notes {
		if n == "Congestion Notification Packet — RoCE explicit congestion control (DCQCN), not a data transfer" {
			foundCNP = true
		}
	}
	if !foundCNP {
		t.Error("expected CNP note")
	}
}

func TestPayloadSurfaced(t *testing.T) {
	// 12-byte BTH + 4 trailing bytes (e.g. the ICRC / start of an ETH).
	r, err := Decode("0c00ffff0000012380000456deadbeef")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.PayloadHex != "DEADBEEF" {
		t.Errorf("PayloadHex = %q, want DEADBEEF", r.PayloadHex)
	}
}

func TestUnknownOpcode(t *testing.T) {
	// 0x1F is not in the IBA table; transport-service bits still decode (RC).
	r, err := Decode("1f00ffff0000012380000456")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "0x1F" {
		t.Errorf("OpcodeName = %q, want 0x1F", r.OpcodeName)
	}
	if r.TransportService != "RC (Reliable Connection)" {
		t.Errorf("TransportService = %q", r.TransportService)
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "0c00ffff00000123800004", "zz"} { // empty, 11 bytes, non-hex
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
