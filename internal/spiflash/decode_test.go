// SPDX-License-Identifier: AGPL-3.0-or-later

package spiflash

import "testing"

func TestRDIDWinbond(t *testing.T) {
	// RDID (0x9F) + the JEDEC readback EF 40 18 = Winbond W25Q128 (16 MB).
	r, err := Decode("9fef4018")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "RDID (Read JEDEC ID)" {
		t.Errorf("CommandName = %q", r.CommandName)
	}
	if r.ManufacturerID != "0xEF" || r.ManufacturerName != "Winbond" {
		t.Errorf("manufacturer = %q/%q", r.ManufacturerID, r.ManufacturerName)
	}
	if r.MemoryTypeHex != "0x40" {
		t.Errorf("MemoryTypeHex = %q", r.MemoryTypeHex)
	}
	if r.CapacityCodeHex != "0x18" {
		t.Errorf("CapacityCodeHex = %q", r.CapacityCodeHex)
	}
	if r.TypicalCapacity != "typical 16 MB (2^24 bytes)" {
		t.Errorf("TypicalCapacity = %q", r.TypicalCapacity)
	}
}

func TestReadCommandAddress(t *testing.T) {
	r, err := Decode("03001000")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "READ (Read Data)" {
		t.Errorf("CommandName = %q", r.CommandName)
	}
	if r.Address != "0x001000" {
		t.Errorf("Address = %q, want 0x001000", r.Address)
	}
}

func TestSectorEraseAddress(t *testing.T) {
	r, err := Decode("200abcde")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "SE (Sector Erase, 4 KB)" {
		t.Errorf("CommandName = %q", r.CommandName)
	}
	if r.Address != "0x0ABCDE" {
		t.Errorf("Address = %q, want 0x0ABCDE", r.Address)
	}
}

func TestWriteEnableNoAddress(t *testing.T) {
	r, err := Decode("06")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "WREN (Write Enable)" {
		t.Errorf("CommandName = %q", r.CommandName)
	}
	if r.Address != "" {
		t.Errorf("WREN should have no address, got %q", r.Address)
	}
}

func TestPageProgramWithData(t *testing.T) {
	r, err := Decode("02000000deadbeef")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "PP (Page Program)" {
		t.Errorf("CommandName = %q", r.CommandName)
	}
	if r.Address != "0x000000" {
		t.Errorf("Address = %q", r.Address)
	}
	if r.PayloadHex != "DEADBEEF" {
		t.Errorf("PayloadHex = %q", r.PayloadHex)
	}
}

func TestRDIDMacronix(t *testing.T) {
	// C2 20 18 = Macronix MX25L12835F (16 MB).
	r, err := Decode("9fc22018")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ManufacturerName != "Macronix (MXIC)" {
		t.Errorf("ManufacturerName = %q", r.ManufacturerName)
	}
}

func TestUnknownCommand(t *testing.T) {
	r, err := Decode("77")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "unknown / vendor-specific command 0x77" {
		t.Errorf("CommandName = %q", r.CommandName)
	}
}

func TestRDIDWithoutReadback(t *testing.T) {
	// Just the RDID opcode — note that the readback is needed.
	r, err := Decode("9f")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ManufacturerName != "" {
		t.Errorf("no readback should not yield a manufacturer, got %q", r.ManufacturerName)
	}
	found := false
	for _, n := range r.Notes {
		if len(n) > 4 && n[:4] == "RDID" {
			found = true
		}
	}
	if !found {
		t.Error("expected a note about including the RDID readback")
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
