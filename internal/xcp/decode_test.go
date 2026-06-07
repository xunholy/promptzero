// SPDX-License-Identifier: AGPL-3.0-or-later

package xcp

import "testing"

// Code tables are generated from scapy.contrib.automotive.xcp; vectors exercise
// each PID class and direction.

func TestCommandConnect(t *testing.T) {
	r, err := Decode("ff00", "command")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Kind != "command" || r.Name != "CONNECT" {
		t.Errorf("kind/name = %q/%q", r.Kind, r.Name)
	}
	if r.SecurityRelevance == "" {
		t.Error("CONNECT should carry a security note")
	}
	if r.PayloadHex != "00" {
		t.Errorf("PayloadHex = %q", r.PayloadHex)
	}
}

func TestCommandGetSeedSecurity(t *testing.T) {
	r, err := Decode("f80000", "command")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Name != "GET_SEED" {
		t.Errorf("Name = %q", r.Name)
	}
	if r.SecurityRelevance == "" {
		t.Error("GET_SEED should flag SEED & KEY auth")
	}
}

func TestCommandUploadAndProgram(t *testing.T) {
	up, _ := Decode("f508", "command")
	if up.Name != "UPLOAD" {
		t.Errorf("UPLOAD name = %q", up.Name)
	}
	if up.SecurityRelevance == "" {
		t.Error("UPLOAD should flag memory read")
	}
	pg, _ := Decode("d0010203", "command")
	if pg.Name != "PROGRAM" {
		t.Errorf("PROGRAM name = %q", pg.Name)
	}
	if pg.SecurityRelevance == "" {
		t.Error("PROGRAM should flag flashing")
	}
}

func TestResponseError(t *testing.T) {
	r, err := Decode("fe24", "response")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Kind != "error" || r.Name != "ERR (negative response)" {
		t.Errorf("kind/name = %q/%q", r.Kind, r.Name)
	}
	if r.ErrorCodeHex != "0x24" || r.ErrorName != "ERR_ACCESS_DENIED" {
		t.Errorf("error = %q/%q", r.ErrorCodeHex, r.ErrorName)
	}
}

func TestResponseEvent(t *testing.T) {
	r, err := Decode("fd07", "response")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Kind != "event" || r.EventName != "EV_SESSION_TERMINATED" {
		t.Errorf("kind/event = %q/%q", r.Kind, r.EventName)
	}
}

func TestResponsePositive(t *testing.T) {
	r, err := Decode("ff0102", "response")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Kind != "positive_response" || r.Name != "RES (positive response)" {
		t.Errorf("kind/name = %q/%q", r.Kind, r.Name)
	}
}

func TestDirectionAmbiguity(t *testing.T) {
	// 0xFF with no direction → command CONNECT, with an ambiguity note.
	r, err := Decode("ff00", "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Name != "CONNECT" {
		t.Errorf("default direction should interpret 0xFF as CONNECT, got %q", r.Name)
	}
	found := false
	for _, n := range r.Notes {
		if len(n) > 20 && n[:9] == "direction" {
			found = true
		}
	}
	if !found {
		t.Error("expected an ambiguity note when direction is unspecified")
	}
}

func TestStimVsDaq(t *testing.T) {
	stim, _ := Decode("0500", "command")
	if stim.Kind != "stim" {
		t.Errorf("PID 0x05 command should be stim, got %q", stim.Kind)
	}
	daq, _ := Decode("0500", "response")
	if daq.Kind != "daq" {
		t.Errorf("PID 0x05 response should be daq, got %q", daq.Kind)
	}
}

func TestErrors(t *testing.T) {
	if _, err := Decode("", "command"); err == nil {
		t.Error("empty should error")
	}
	if _, err := Decode("zz", "command"); err == nil {
		t.Error("non-hex should error")
	}
	if _, err := Decode("ff", "sideways"); err == nil {
		t.Error("bad direction should error")
	}
}
