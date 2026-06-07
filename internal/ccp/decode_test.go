// SPDX-License-Identifier: AGPL-3.0-or-later

package ccp

import "testing"

// Code tables are generated from scapy.contrib.automotive.ccp; vectors exercise
// the CRO commands and DTO responses.

func TestCROConnect(t *testing.T) {
	// cmd CONNECT (0x01), ctr 0x2A, station address 0x0102 (little-endian 0201).
	r, err := Decode("012a0201ffffffff", "command")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Command != "CONNECT" {
		t.Errorf("Command = %q", r.Command)
	}
	if r.CommandCounter == nil || *r.CommandCounter != 0x2A {
		t.Errorf("CommandCounter = %v", r.CommandCounter)
	}
	if r.StationAddress != "0x0102" {
		t.Errorf("StationAddress = %q, want 0x0102 (little-endian)", r.StationAddress)
	}
	if r.SecurityRelevance == "" {
		t.Error("CONNECT should carry a security note")
	}
}

func TestCROGetSeedSecurity(t *testing.T) {
	r, err := Decode("122b01", "command")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Command != "GET_SEED" {
		t.Errorf("Command = %q", r.Command)
	}
	if r.SecurityRelevance == "" {
		t.Error("GET_SEED should flag SEED & KEY auth")
	}
}

func TestCROUploadAndProgram(t *testing.T) {
	up, _ := Decode("042b05a00000", "command")
	if up.Command != "UPLOAD" || up.SecurityRelevance == "" {
		t.Errorf("UPLOAD = %q / sec %q", up.Command, up.SecurityRelevance)
	}
	pg, _ := Decode("182c", "command")
	if pg.Command != "PROGRAM" || pg.SecurityRelevance == "" {
		t.Errorf("PROGRAM = %q / sec %q", pg.Command, pg.SecurityRelevance)
	}
}

func TestDTOCommandReturnMessageAck(t *testing.T) {
	// pid 0xFF (CRM), return_code 0x00 (ack), ctr 0x2A.
	r, err := Decode("ff002a", "response")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.DTOType != "Command Return Message (CRM)" {
		t.Errorf("DTOType = %q", r.DTOType)
	}
	if r.ReturnCode != "acknowledge / no error" {
		t.Errorf("ReturnCode = %q", r.ReturnCode)
	}
	if r.Counter == nil || *r.Counter != 0x2A {
		t.Errorf("Counter = %v", r.Counter)
	}
}

func TestDTOAccessDenied(t *testing.T) {
	// pid 0xFF, return_code 0x33 (access denied).
	r, err := Decode("ff332b", "response")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ReturnCode != "access denied" {
		t.Errorf("ReturnCode = %q", r.ReturnCode)
	}
}

func TestDTOEventAndDAQ(t *testing.T) {
	ev, _ := Decode("fe19", "response")
	if ev.DTOType != "Event message" {
		t.Errorf("DTOType = %q", ev.DTOType)
	}
	daq, _ := Decode("05aabbccdd", "response")
	if daq.DTOType != "DAQ-DTO (ODT number 5 — measurement data)" {
		t.Errorf("DAQ DTOType = %q", daq.DTOType)
	}
}

func TestDirectionAmbiguity(t *testing.T) {
	// 0x12 with no direction → command GET_SEED, with an ambiguity note.
	r, err := Decode("122b01", "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Command != "GET_SEED" {
		t.Errorf("default direction should interpret 0x12 as GET_SEED, got %q", r.Command)
	}
	found := false
	for _, n := range r.Notes {
		if len(n) >= 9 && n[:9] == "direction" {
			found = true
		}
	}
	if !found {
		t.Error("expected an ambiguity note when direction is unspecified")
	}
}

func TestErrors(t *testing.T) {
	if _, err := Decode("", "command"); err == nil {
		t.Error("empty should error")
	}
	if _, err := Decode("zz", "command"); err == nil {
		t.Error("non-hex should error")
	}
	if _, err := Decode("01", "sideways"); err == nil {
		t.Error("bad direction should error")
	}
}
