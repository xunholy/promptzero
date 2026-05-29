// SPDX-License-Identifier: AGPL-3.0-or-later

package ethercat

import "testing"

// TestDecode_BroadcastReadALStatus pins the canonical EtherCAT frame a
// master emits to poll every slave's AL Status register (ADO 0x0130).
//
//	Header:   0E 10            (Length 14, Type 1 = command)
//	Datagram: 07 00            BRD, index 0
//	          00 00 30 01      ADP 0, ADO 0x0130 (AL Status)
//	          02 00            data length 2, no flags
//	          00 00            IRQ
//	          00 00            data (read placeholder)
//	          01 00            working counter 1
func TestDecode_BroadcastReadALStatus(t *testing.T) {
	got, err := Decode("0E10 0700 0000 3001 0200 0000 0000 0100")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Length != 14 {
		t.Errorf("Length = %d; want 14", got.Length)
	}
	if got.Type != 1 || got.TypeName != "EtherCAT commands (DLPDU)" {
		t.Errorf("Type = %d (%q)", got.Type, got.TypeName)
	}
	if len(got.Datagrams) != 1 {
		t.Fatalf("Datagrams = %d; want 1", len(got.Datagrams))
	}
	d := got.Datagrams[0]
	if d.CommandName != "BRD (broadcast read)" {
		t.Errorf("CommandName = %q", d.CommandName)
	}
	if d.ADO == nil || *d.ADO != 0x0130 {
		t.Errorf("ADO = %v; want 0x0130", d.ADO)
	}
	if d.AddressMode != "position+offset (ADP/ADO)" {
		t.Errorf("AddressMode = %q", d.AddressMode)
	}
	if d.DataLength != 2 || d.DataHex != "0000" {
		t.Errorf("DataLength=%d DataHex=%q", d.DataLength, d.DataHex)
	}
	if d.WorkingCounter != 1 {
		t.Errorf("WorkingCounter = %d; want 1", d.WorkingCounter)
	}
}

// TestDecode_ChainedDatagrams exercises the More-follows (M) bit
// chaining two datagrams and the logical-addressing branch.
//
//	Header: 1B 10  (Length 27, Type 1)
//	DG1: APRD, M=1, ADP/ADO 0, data len 1 = AA, WKC 0
//	DG2: LWR, logical address 0x00010000, data len 2 = 11 22, WKC 1
func TestDecode_ChainedDatagrams(t *testing.T) {
	in := "1B10" +
		"0100 0000 0000 0180 0000 AA 0000" + // DG1 APRD, more=1
		"0B00 00000100 0200 0000 1122 0100" // DG2 LWR logical
	got, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.Datagrams) != 2 {
		t.Fatalf("Datagrams = %d; want 2", len(got.Datagrams))
	}
	d1 := got.Datagrams[0]
	if d1.CommandName != "APRD (auto-increment read)" {
		t.Errorf("DG1 CommandName = %q", d1.CommandName)
	}
	if !d1.MoreFollows {
		t.Error("DG1 MoreFollows = false; want true")
	}
	if d1.DataHex != "AA" {
		t.Errorf("DG1 DataHex = %q; want AA", d1.DataHex)
	}
	d2 := got.Datagrams[1]
	if d2.CommandName != "LWR (logical write)" {
		t.Errorf("DG2 CommandName = %q", d2.CommandName)
	}
	if d2.AddressMode != "logical (32-bit)" {
		t.Errorf("DG2 AddressMode = %q", d2.AddressMode)
	}
	if d2.LogicalAddress == nil || *d2.LogicalAddress != 0x00010000 {
		t.Errorf("DG2 LogicalAddress = %v; want 0x00010000", d2.LogicalAddress)
	}
	if d2.DataHex != "1122" || d2.WorkingCounter != 1 {
		t.Errorf("DG2 DataHex=%q WKC=%d", d2.DataHex, d2.WorkingCounter)
	}
}

// TestDecode_MailboxTypeSurfaced confirms a non-command frame type is
// classified and its body surfaced rather than walked as datagrams.
//
//	Header: 04 50  (Length 4, Type 5 = mailbox)
func TestDecode_MailboxTypeSurfaced(t *testing.T) {
	got, err := Decode("0450 DEADBEEF")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Type != 5 || got.TypeName != "Mailbox" {
		t.Errorf("Type = %d (%q); want 5 Mailbox", got.Type, got.TypeName)
	}
	if len(got.Datagrams) != 0 {
		t.Errorf("Datagrams = %d; want 0", len(got.Datagrams))
	}
	if got.DatagramHex != "DEADBEEF" {
		t.Errorf("DatagramHex = %q; want DEADBEEF", got.DatagramHex)
	}
}

// TestDecode_OversizedLengthNoPanic feeds a header Length larger than
// the buffer and a truncated datagram; the walk must clamp and not
// panic, surfacing a note.
func TestDecode_OversizedLengthNoPanic(t *testing.T) {
	// Header claims Length 0x7FF (2047) but only a few body bytes follow.
	in := "FF1F 0700 0000"
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Decode panicked on oversized length: %v", r)
		}
	}()
	got, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.Notes) == 0 {
		t.Error("expected an oversized-length note")
	}
	// The single truncated datagram (< 10 header bytes after clamp)
	// cannot be decoded, so no datagrams are produced.
	if len(got.Datagrams) != 0 {
		t.Errorf("Datagrams = %d; want 0 (truncated)", len(got.Datagrams))
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":    "",
		"bad hex":  "zz",
		"one byte": "0E",
		"odd hex":  "0E1",
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
