// SPDX-License-Identifier: AGPL-3.0-or-later

package canfd

import (
	"strings"
	"testing"
)

func TestDecode_ClassicStandard(t *testing.T) {
	r, err := Decode("123#DEADBEEF")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Extended || r.IDBits != 11 {
		t.Errorf("Extended=%v IDBits=%d; want standard 11-bit", r.Extended, r.IDBits)
	}
	if r.IDDecimal != 0x123 {
		t.Errorf("IDDecimal = 0x%X; want 0x123", r.IDDecimal)
	}
	if r.FDF {
		t.Errorf("FDF = true; want classic")
	}
	if r.DataLength != 4 || r.DataHex != "DEADBEEF" {
		t.Errorf("data = %d/%q; want 4/DEADBEEF", r.DataLength, r.DataHex)
	}
	if r.DLC != 4 {
		t.Errorf("DLC = %d; want 4", r.DLC)
	}
}

func TestDecode_ClassicRejectsOver8Bytes(t *testing.T) {
	if _, err := Decode("123#00112233445566778899"); err == nil {
		t.Error("want error for classic CAN frame > 8 data bytes")
	}
}

func TestDecode_ClassicRemoteFrame(t *testing.T) {
	r, err := Decode("7DF#R")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.RTR {
		t.Errorf("RTR = false; want true for remote frame")
	}
}

func TestDecode_FDWithFlags(t *testing.T) {
	// "##3" → flags nibble 3 = BRS(1) | ESI(2), then 16 data bytes.
	data := strings.Repeat("A1", 16)
	r, err := Decode("18DAF110##3" + data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.FDF {
		t.Errorf("FDF = false; want CAN-FD")
	}
	if !r.BRS || !r.ESI {
		t.Errorf("BRS=%v ESI=%v; want both set from flags nibble 3", r.BRS, r.ESI)
	}
	if r.DataLength != 16 {
		t.Errorf("DataLength = %d; want 16", r.DataLength)
	}
	if r.DLC != 10 { // 16 bytes → DLC 10
		t.Errorf("DLC = %d; want 10 for 16-byte CAN-FD payload", r.DLC)
	}
	if !r.Extended || r.IDBits != 29 {
		t.Errorf("Extended=%v IDBits=%d; want extended 29-bit", r.Extended, r.IDBits)
	}
}

func TestDecode_FD64Bytes(t *testing.T) {
	r, err := Decode("100##0" + strings.Repeat("FF", 64))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.DataLength != 64 || r.DLC != 15 {
		t.Errorf("64-byte payload: DataLength=%d DLC=%d; want 64/15", r.DataLength, r.DLC)
	}
	if r.BRS || r.ESI {
		t.Errorf("flags nibble 0 → BRS/ESI should be clear; got BRS=%v ESI=%v", r.BRS, r.ESI)
	}
}

func TestDecode_FDIllegalLengthNoted(t *testing.T) {
	// 9 bytes is not a legal CAN-FD length (only 0-8,12,16,...).
	r, err := Decode("200##0" + strings.Repeat("11", 9))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.DLC != -1 {
		t.Errorf("DLC = %d; want -1 for illegal length", r.DLC)
	}
	if len(r.Notes) == 0 || !containsSub(r.Notes, "not a legal CAN-FD length") {
		t.Errorf("expected an illegal-length note; got %v", r.Notes)
	}
}

// TestDecode_J1939_PDU2 checks a broadcast (PF>=240) PGN — the classic
// J1939 EEC1 (engine) example uses PF 0xF0 0x04 → PGN 0xF004 (61444).
func TestDecode_J1939_PDU2(t *testing.T) {
	// 29-bit ID: priority 3 (110 << 26), PF=0xF0, PS=0x04, SA=0x00.
	// 0x0CF00400.
	r, err := Decode("0CF00400##10001020304050607")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.J1939 == nil {
		t.Fatal("J1939 = nil; want decomposition for 29-bit ID")
	}
	j := r.J1939
	if j.Priority != 3 {
		t.Errorf("Priority = %d; want 3", j.Priority)
	}
	if j.PDUFormat != 0xF0 || j.PDUSpecific != 0x04 {
		t.Errorf("PF/PS = 0x%X/0x%X; want 0xF0/0x04", j.PDUFormat, j.PDUSpecific)
	}
	if j.PGN != 0xF004 {
		t.Errorf("PGN = 0x%X; want 0xF004 (61444, EEC1)", j.PGN)
	}
	if j.Kind != "PDU2 (broadcast)" {
		t.Errorf("Kind = %q; want PDU2", j.Kind)
	}
	if j.DestAddress != nil {
		t.Errorf("DestAddress = %v; PDU2 has no destination", j.DestAddress)
	}
	if j.SourceAddress != 0x00 {
		t.Errorf("SourceAddress = 0x%X; want 0x00", j.SourceAddress)
	}
}

// TestDecode_J1939_PDU1 checks a destination-specific (PF<240) frame:
// PS is the destination address and is excluded from the PGN.
func TestDecode_J1939_PDU1(t *testing.T) {
	// priority 6, PF=0xEA (234, < 240), PS=0x21 (dest), SA=0xF9.
	// 0x18EA21F9.
	r, err := Decode("18EA21F9##10001020304050607")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	j := r.J1939
	if j == nil {
		t.Fatal("J1939 = nil")
	}
	if j.Kind != "PDU1 (destination-specific)" {
		t.Errorf("Kind = %q; want PDU1", j.Kind)
	}
	if j.DestAddress == nil || *j.DestAddress != 0x21 {
		t.Errorf("DestAddress = %v; want 0x21", j.DestAddress)
	}
	if j.PGN != 0xEA00 {
		t.Errorf("PGN = 0x%X; want 0xEA00 (PS excluded for PDU1)", j.PGN)
	}
	if j.SourceAddress != 0xF9 {
		t.Errorf("SourceAddress = 0x%X; want 0xF9", j.SourceAddress)
	}
}

func TestDecode_CandumpLineTolerated(t *testing.T) {
	// A full `candump -L` line: (timestamp) interface frame.
	r, err := Decode("(1620000000.000000) can0 123#AABB")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.IDDecimal != 0x123 || r.DataHex != "AABB" {
		t.Errorf("got ID=0x%X data=%q; want 0x123/AABB from candump line", r.IDDecimal, r.DataHex)
	}
}

func TestDecode_StandardVsExtendedByLength(t *testing.T) {
	// Zero-padded 8-char ID with a small value must be read as extended.
	r, err := Decode("00000123##000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Extended || r.IDBits != 29 {
		t.Errorf("padded 8-char ID: Extended=%v IDBits=%d; want extended", r.Extended, r.IDBits)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"no hash":       "123ABCDEF",
		"missing id":    "#AABB",
		"bad id":        "ZZ#AABB",
		"odd data":      "123#ABC",
		"id overflow":   "FFFFFFFF##00",
		"fd no flags":   "123##",
		"bad data char": "123#GG",
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s (%q): expected error, got nil", name, in)
		}
	}
}

func containsSub(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
