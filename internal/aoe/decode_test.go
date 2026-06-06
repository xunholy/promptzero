// SPDX-License-Identifier: AGPL-3.0-or-later

package aoe

import "testing"

// The structural fields of these vectors were verified by parsing the same
// bytes with scapy's AoE layer (scapy.contrib.aoe). The Response/Error flag
// bits are asserted per the AoE spec / Wireshark (0x08 / 0x04); scapy maps
// those bits incorrectly, so the spec is the authority (see the package doc).

func TestDecodeATARead(t *testing.T) {
	// shelf 1, slot 2, cmd 0, tag DEADBEEF; ATA READ (0x20), 8 sectors, LBA 0x123456.
	const v = "100000010200deadbeef400008205634120000000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 1 || r.Shelf != 1 || r.Slot != 2 {
		t.Fatalf("ver/shelf/slot = %d/%d/%d", r.Version, r.Shelf, r.Slot)
	}
	if r.CmdName != "Issue ATA Command" || r.Tag != "0xDEADBEEF" {
		t.Errorf("cmd/tag = %q/%q", r.CmdName, r.Tag)
	}
	if r.ATA == nil {
		t.Fatal("ATA body not decoded")
	}
	if r.ATA.ATACmd != 0x20 || r.ATA.ATACmdName != "READ SECTORS" {
		t.Errorf("ata cmd = %#x/%q", r.ATA.ATACmd, r.ATA.ATACmdName)
	}
	if r.ATA.SectorCount != 8 {
		t.Errorf("sector count = %d, want 8", r.ATA.SectorCount)
	}
	if r.ATA.LBA != 0x123456 {
		t.Errorf("LBA = %#x, want 0x123456", r.ATA.LBA)
	}
}

func TestDecodeQueryConfig(t *testing.T) {
	// shelf 5, slot 3, cmd 1; buffer 0x10, firmware 0x0102, ccmd 0, config "CORAID EtherDrive".
	const v = "100000050301000000010010010202400011" + "434f524149442045746865724472697665"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CmdName != "Query Config Information" || r.Query == nil {
		t.Fatalf("cmd/query = %q/%v", r.CmdName, r.Query)
	}
	if r.Query.BufferCount != 0x10 || r.Query.Firmware != 0x0102 {
		t.Errorf("buffer/fw = %#x/%#x", r.Query.BufferCount, r.Query.Firmware)
	}
	if r.Query.AoEVersion != 4 || r.Query.ConfigCmd != 0 {
		t.Errorf("aoe/ccmd = %d/%d", r.Query.AoEVersion, r.Query.ConfigCmd)
	}
	if r.Query.ConfigStr != "CORAID EtherDrive" {
		t.Errorf("config = %q", r.Query.ConfigStr)
	}
}

func TestDecodeResponseErrorFlags(t *testing.T) {
	// byte0 = 0x1c -> version 1, flags nibble 0xc = Response(0x08) + Error(0x04).
	const v = "1c060005030100000001"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Response || !r.Error {
		t.Errorf("Response/Error = %v/%v, want true/true", r.Response, r.Error)
	}
	if r.ErrorCode != 6 || r.ErrorName != "Target is reserved" {
		t.Errorf("error = %d/%q", r.ErrorCode, r.ErrorName)
	}
}

func TestDecodeWriteCommand(t *testing.T) {
	// ATA WRITE EXT (0x34) is read-vs-write intent without needing aflags.
	const v = "100000010300cafebabe000010340000000000000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ATA == nil || r.ATA.ATACmdName != "WRITE SECTORS EXT" {
		t.Errorf("ata = %+v", r.ATA)
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("1000000102"); err == nil {
		t.Fatal("expected error on short header")
	}
}
