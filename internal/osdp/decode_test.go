// SPDX-License-Identifier: AGPL-3.0-or-later

package osdp

import (
	"encoding/hex"
	"testing"
)

// The packet vectors are taken from the libosdp phy-layer unit tests
// (tests/unit-tests/test-cp-phy.c) — real on-the-wire OSDP frames with
// the reference CRC / checksum trailers.

func TestDecodePollCommand(t *testing.T) {
	// CMD_POLL to address 0x65, CRC mode. 53 65 08 00 04 60 60 90
	r, err := Decode("53 65 08 00 04 60 60 90")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Direction != "command (CP->PD)" {
		t.Errorf("direction = %q", r.Direction)
	}
	if r.PDAddress != 0x65 {
		t.Errorf("pd_address = 0x%02X, want 0x65", r.PDAddress)
	}
	if r.CodeName != "osdp_POLL" {
		t.Errorf("code_name = %q, want osdp_POLL", r.CodeName)
	}
	if r.CheckMode != "crc" || !r.TrailerValid {
		t.Errorf("check = %s, valid = %v, want crc/true", r.CheckMode, r.TrailerValid)
	}
	if r.SequenceNumber != 0 {
		t.Errorf("seq = %d, want 0", r.SequenceNumber)
	}
}

func TestDecodeIDCommand(t *testing.T) {
	// CMD_ID, data {0x00}, CRC mode. 53 65 09 00 04 61 00 d9 7a
	r, err := Decode("5365090004610 0d97a")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CodeName != "osdp_ID" || r.DataHex != "00" || !r.TrailerValid {
		t.Errorf("got %+v", r)
	}
}

func TestDecodeACKReplyChecksum(t *testing.T) {
	// REPLY_ACK from 0x65, checksum mode (control 0x01). 53 e5 07 00 01 40 80
	r, err := Decode("53 e5 07 00 01 40 80")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Direction != "reply (PD->CP)" {
		t.Errorf("direction = %q", r.Direction)
	}
	if r.PDAddress != 0x65 {
		t.Errorf("pd_address = 0x%02X, want 0x65", r.PDAddress)
	}
	if r.CodeName != "osdp_ACK" {
		t.Errorf("code_name = %q, want osdp_ACK", r.CodeName)
	}
	if r.CheckMode != "checksum" || !r.TrailerValid {
		t.Errorf("check = %s, valid = %v, want checksum/true", r.CheckMode, r.TrailerValid)
	}
	if r.SequenceNumber != 1 {
		t.Errorf("seq = %d, want 1", r.SequenceNumber)
	}
}

func TestDecodeNAKReply(t *testing.T) {
	// REPLY_NAK, error 0x01, CRC mode. 53 e5 09 00 05 41 01 0e 8f
	r, err := Decode("53 e5 09 00 05 41 01 0e 8f")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CodeName != "osdp_NAK" {
		t.Errorf("code_name = %q, want osdp_NAK", r.CodeName)
	}
	if r.NAKError == nil || *r.NAKError != 1 {
		t.Fatalf("nak error = %v, want 1", r.NAKError)
	}
	if r.NAKErrorName != "message check character(s) error (bad checksum/CRC)" {
		t.Errorf("nak name = %q", r.NAKErrorName)
	}
	if !r.TrailerValid {
		t.Errorf("trailer should be valid; computed %s vs %s", r.TrailerComputed, r.TrailerHex)
	}
}

func TestDecodeWithMarkByte(t *testing.T) {
	// Same POLL packet with the 0xFF driver mark prepended.
	r, err := Decode("FF 53 65 08 00 04 60 60 90")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.HasMark || r.CodeName != "osdp_POLL" || !r.TrailerValid {
		t.Errorf("mark/POLL/valid = %v/%q/%v", r.HasMark, r.CodeName, r.TrailerValid)
	}
}

func TestDecodeCorruptTrailer(t *testing.T) {
	// Flip the last CRC byte — must report invalid, not error.
	r, err := Decode("53 65 08 00 04 60 60 91")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TrailerValid {
		t.Error("expected trailer_valid=false for a corrupted CRC")
	}
}

func TestDecodeRejects(t *testing.T) {
	for _, c := range []string{"", "53", "00 65 08 00 04 60 60 90", "53 65 FF 00 04 60"} {
		if _, err := Decode(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

// TestCRCKnownVector pins the CRC-16/AUG-CCITT against the POLL header.
func TestCRCKnownVector(t *testing.T) {
	covered, _ := hex.DecodeString("536508000460") // SOM..code, sans trailer
	if got := crc16AugCCITT(covered); got != 0x9060 {
		t.Errorf("CRC = 0x%04X, want 0x9060", got)
	}
}

// FuzzDecode asserts the parser never panics.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"53 65 08 00 04 60 60 90", "FF 53 e5 07 00 01 40 80",
		"53 e5 09 00 05 41 01 0e 8f", "", "53",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s)
	})
}
