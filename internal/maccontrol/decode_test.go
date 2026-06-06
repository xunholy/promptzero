// SPDX-License-Identifier: AGPL-3.0-or-later

package maccontrol

import (
	"strings"
	"testing"
)

// Vectors produced with scapy's MACControl layer (scapy.contrib.mac_control)
// and verified field-for-field. Frames are padded to the 60-byte minimum.

func TestDecodePause(t *testing.T) {
	const v = "0001ffff" + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "PAUSE" {
		t.Fatalf("opcode = %q", r.OpcodeName)
	}
	if r.PauseTimeQuanta == nil || *r.PauseTimeQuanta != 0xffff {
		t.Errorf("pause time = %v, want 65535", r.PauseTimeQuanta)
	}
	var dos bool
	for _, n := range r.Notes {
		if strings.Contains(n, "flow-control DoS") {
			dos = true
		}
	}
	if !dos {
		t.Error("expected a DoS note for PAUSE")
	}
}

func TestDecodePFC(t *testing.T) {
	// PFC: reserved 00, enable 0x85 (c0,c2,c7), times c0=100 c2=200 c7=300
	const v = "010100850064000000c80000000000000000012c00000000000000000000000000000000000000000000000000000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "PFC / Class-Based Flow Control" {
		t.Fatalf("opcode = %q", r.OpcodeName)
	}
	if len(r.PFCClasses) != 8 {
		t.Fatalf("classes = %d, want 8", len(r.PFCClasses))
	}
	if !r.PFCClasses[0].Enabled || r.PFCClasses[0].PauseTime != 100 {
		t.Errorf("class0 = %+v", r.PFCClasses[0])
	}
	if r.PFCClasses[1].Enabled {
		t.Errorf("class1 should be disabled")
	}
	if !r.PFCClasses[2].Enabled || r.PFCClasses[2].PauseTime != 200 {
		t.Errorf("class2 = %+v", r.PFCClasses[2])
	}
	if !r.PFCClasses[7].Enabled || r.PFCClasses[7].PauseTime != 300 {
		t.Errorf("class7 = %+v", r.PFCClasses[7])
	}
}

func TestDecodeReport(t *testing.T) {
	// REPORT: opcode 0003, timestamp 0x01020304, flags=1(register), pending=2
	const v = "00030102030401020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "REPORT (MPCP)" {
		t.Fatalf("opcode = %q", r.OpcodeName)
	}
	if r.Timestamp == nil || *r.Timestamp != 0x01020304 {
		t.Errorf("timestamp = %v", r.Timestamp)
	}
	if r.Flags == nil || *r.Flags != 1 || r.FlagsName != "register" {
		t.Errorf("flags = %v/%q", r.Flags, r.FlagsName)
	}
	if r.PendingGrants == nil || *r.PendingGrants != 2 {
		t.Errorf("pending = %v", r.PendingGrants)
	}
}

func TestDecodeTrailingNoted(t *testing.T) {
	// PAUSE with a non-zero byte in the padding region
	const v = "0001ffff00ff0000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var noted bool
	for _, n := range r.Notes {
		if strings.Contains(n, "non-zero trailing") {
			noted = true
		}
	}
	if !noted {
		t.Error("expected a non-zero-trailing note")
	}
}

func TestDecodeUnknownOpcode(t *testing.T) {
	r, err := Decode("0999aabbccdd")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.BodyHex != "AABBCCDD" {
		t.Errorf("body = %q", r.BodyHex)
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("00"); err == nil {
		t.Fatal("expected error on short input")
	}
	if _, err := Decode("0001"); err == nil {
		t.Fatal("expected error on truncated PAUSE")
	}
}
