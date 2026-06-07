// SPDX-License-Identifier: AGPL-3.0-or-later

package hci

import (
	"strings"
	"testing"
)

func TestResetCommand(t *testing.T) {
	// 01 (Command) | 03 0C (opcode 0x0C03 LE) | 00 (param len).
	r, err := Decode("01030c00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.PacketType != "Command" {
		t.Errorf("PacketType = %q", r.PacketType)
	}
	if r.OpcodeHex != "0x0C03" || r.CommandName != "Reset" {
		t.Errorf("opcode/name = %q/%q", r.OpcodeHex, r.CommandName)
	}
	if !strings.Contains(r.OGF, "Controller & Baseband") {
		t.Errorf("OGF = %q", r.OGF)
	}
}

func TestLESetScanEnable(t *testing.T) {
	// 01 | 0C 20 (opcode 0x200C) | 02 | 01 00.
	r, err := Decode("010c20020100")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "LE Set Scan Enable" {
		t.Errorf("CommandName = %q", r.CommandName)
	}
	if !strings.Contains(r.OGF, "LE Controller") {
		t.Errorf("OGF = %q", r.OGF)
	}
	if r.ParamLength != 2 || r.ParamsHex != "0100" {
		t.Errorf("params = %d/%q", r.ParamLength, r.ParamsHex)
	}
}

func TestCommandCompleteEmbedsOpcode(t *testing.T) {
	// 04 (Event) | 0E (Command Complete) | 04 | 01 (num pkts) 03 0C (opcode) 00 (status).
	r, err := Decode("040e0401030c00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.EventName != "Command Complete" {
		t.Errorf("EventName = %q", r.EventName)
	}
	if r.ForOpcodeHex != "0x0C03" || r.ForCommand != "Reset" {
		t.Errorf("for-command = %q/%q", r.ForOpcodeHex, r.ForCommand)
	}
}

func TestLEMetaAdvertisingReport(t *testing.T) {
	// 04 | 3E (LE Meta) | 0C | 02 (subevent LE Adv Report) + 11 bytes.
	r, err := Decode("043e0c020100112233445566778899")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.EventName != "LE Meta" {
		t.Errorf("EventName = %q", r.EventName)
	}
	if r.SubeventName != "LE Advertising Report" {
		t.Errorf("SubeventName = %q", r.SubeventName)
	}
}

func TestACLData(t *testing.T) {
	// 02 (ACL) | 40 20 (handle 0x040, PB=2) | 05 00 (len 5) | 5 data bytes.
	r, err := Decode("02402005001122334455")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.PacketType != "ACL Data" {
		t.Errorf("PacketType = %q", r.PacketType)
	}
	if !strings.Contains(r.ConnectionHandle, "0x040") || !strings.Contains(r.ConnectionHandle, "PB=2") {
		t.Errorf("ConnectionHandle = %q", r.ConnectionHandle)
	}
	if r.ParamLength != 5 || r.ParamsHex != "1122334455" {
		t.Errorf("params = %d/%q", r.ParamLength, r.ParamsHex)
	}
}

func TestUnknownOpcodeSurfacesOGFOCF(t *testing.T) {
	// Opcode 0xFFFF → OGF 0x3F (Vendor), OCF 0x3FF.
	r, err := Decode("01ffff00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.CommandName, "OGF 0x3F") || !strings.Contains(r.CommandName, "OCF 0x3FF") {
		t.Errorf("CommandName = %q", r.CommandName)
	}
	if !strings.Contains(r.OGF, "Vendor-Specific") {
		t.Errorf("OGF = %q", r.OGF)
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz", "0101"} {
		// empty, non-hex, truncated command (opcode needs 3 bytes)
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
