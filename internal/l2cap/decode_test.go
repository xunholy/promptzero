// SPDX-License-Identifier: AGPL-3.0-or-later

package l2cap

import "testing"

func TestATTReadRequest(t *testing.T) {
	// length 3, CID 0x0004 (ATT), ATT opcode 0x0A (Read Request) + handle 0x0003.
	r, err := Decode("030004000a0300")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CID != "0x0004" || r.Channel != "att" {
		t.Errorf("CID/channel = %q/%q", r.CID, r.Channel)
	}
	if r.OpcodeHex != "0x0A" || r.Operation != "Read Request" {
		t.Errorf("opcode/op = %q/%q", r.OpcodeHex, r.Operation)
	}
	if r.PayloadHex != "0300" {
		t.Errorf("PayloadHex = %q", r.PayloadHex)
	}
}

func TestATTNotification(t *testing.T) {
	// length 4, CID 0x0004, ATT opcode 0x1B (Handle Value Notification) + handle + value.
	r, err := Decode("04000400" + "1b0500ff")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Operation != "Handle Value Notification" {
		t.Errorf("Operation = %q", r.Operation)
	}
}

func TestSMPPairingRequest(t *testing.T) {
	// CID 0x0006 (SMP), code 0x01 (Pairing Request).
	r, err := Decode("0700060001030005100101")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Channel != "smp" || r.CIDName != "SMP (Security Manager / pairing)" {
		t.Errorf("channel/cidname = %q/%q", r.Channel, r.CIDName)
	}
	if r.Operation != "Pairing Request" {
		t.Errorf("Operation = %q", r.Operation)
	}
}

func TestLESignalingConnParamUpdate(t *testing.T) {
	// CID 0x0005 (LE Signaling), code 0x12 (Connection Parameter Update Request),
	// identifier 0x01, length 0x0008, then 8 bytes.
	r, err := Decode("0c0005001201080010001800000048" + "00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Channel != "signaling" {
		t.Errorf("Channel = %q", r.Channel)
	}
	if r.SignalingCode != "Connection Parameter Update Request" {
		t.Errorf("SignalingCode = %q", r.SignalingCode)
	}
	if r.SignalingID == nil || *r.SignalingID != 1 {
		t.Errorf("SignalingID = %v", r.SignalingID)
	}
}

func TestDynamicCID(t *testing.T) {
	// CID 0x0040 → dynamic channel.
	r, err := Decode("020040001122")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Channel != "dynamic" {
		t.Errorf("Channel = %q, want dynamic", r.Channel)
	}
	if r.PayloadHex != "1122" {
		t.Errorf("PayloadHex = %q", r.PayloadHex)
	}
}

func TestUnknownATTOpcode(t *testing.T) {
	r, err := Decode("010004007f")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Operation != "ATT opcode 0x7F" {
		t.Errorf("Operation = %q", r.Operation)
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "0300", "zz"} {
		// empty, < 4 bytes, non-hex
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
