// SPDX-License-Identifier: AGPL-3.0-or-later

package pfcp

import (
	"strings"
	"testing"
)

// Field values are scapy's (scapy.contrib.pfcp) decode of the same bytes.

func TestDecodeHeartbeat(t *testing.T) {
	// version 1, S=0, message_type 1 (Heartbeat Request), seq 7,
	// one IE: Recovery Time Stamp (type 96, len 4).
	r, err := Decode("2001000c0000070000600004e1234567")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 1 || r.SEIDPresent {
		t.Errorf("version/S = %d/%v", r.Version, r.SEIDPresent)
	}
	if r.MessageType != 1 || r.MessageName != "Heartbeat Request" {
		t.Errorf("type = %d (%q)", r.MessageType, r.MessageName)
	}
	if r.SequenceNumber != 7 || r.SEID != "" {
		t.Errorf("seq/seid = %d/%q", r.SequenceNumber, r.SEID)
	}
	if len(r.IEs) != 1 || r.IEs[0].Type != 96 || r.IEs[0].TypeName != "Recovery Time Stamp" || r.IEs[0].Length != 4 {
		t.Errorf("IE = %+v", r.IEs)
	}
	if r.IEs[0].ValueHex != "E1234567" {
		t.Errorf("IE value = %q", r.IEs[0].ValueHex)
	}
}

func TestDecodeSessionEstablishmentHeader(t *testing.T) {
	// version 1, S=1, message_type 50, seid 0x1122334455667788, seq 0x539.
	r, err := Decode("2132000c112233445566778800053900")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.SEIDPresent || r.SEID != "0x1122334455667788" {
		t.Errorf("SEID = %v / %q", r.SEIDPresent, r.SEID)
	}
	if r.MessageType != 50 || r.MessageName != "Session Establishment Request" {
		t.Errorf("type = %d (%q)", r.MessageType, r.MessageName)
	}
	if r.SequenceNumber != 0x539 {
		t.Errorf("seq = %#x; want 0x539", r.SequenceNumber)
	}
}

func TestDecodeCauseIE(t *testing.T) {
	// Session Deletion Response (mt=55), S=1, with a Cause IE (type 19, value 1).
	// header(16) = 21 37 0005 1122334455667788 000539 00, then 0013 0001 01.
	r, err := Decode("213700051122334455667788000539000013000101")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageType != 55 || r.MessageName != "Session Deletion Response" {
		t.Errorf("type = %d (%q)", r.MessageType, r.MessageName)
	}
	if len(r.IEs) != 1 || r.IEs[0].Type != 19 || r.IEs[0].TypeName != "Cause" || r.IEs[0].Decoded != "cause 1" {
		t.Errorf("Cause IE = %+v", r.IEs)
	}
}

func TestDecodeDeletionAttackNote(t *testing.T) {
	// Session Deletion Request (mt=54) carries the N4-attack note.
	r, err := Decode("2136000c112233445566778800053900")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "tear down or redirect") {
		t.Error("expected the N4 session-attack note")
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "zz", "2001", "4001000000000000"} { // empty / non-hex / short / version 2
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestNames(t *testing.T) {
	if messageName(50) != "Session Establishment Request" || messageName(54) != "Session Deletion Request" {
		t.Error("message name table wrong")
	}
	if ieName(57) != "F-SEID" || ieName(60) != "Node ID" || ieName(96) != "Recovery Time Stamp" {
		t.Error("IE name table wrong")
	}
}

func FuzzDecode(f *testing.F) {
	f.Add("2001000c0000070000600004e1234567")
	f.Add("2132000c112233445566778800053900")
	f.Add("213700051122334455667788000539000013000101")
	f.Add("")
	f.Add("21")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
