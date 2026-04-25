package buspirate

import (
	"testing"
)

// --- ParseI2CScan ---

func TestParseI2CScan_FoundAddresses(t *testing.T) {
	// Fixture: realistic `(1)` macro output from Bus Pirate 5 firmware.
	raw := `
I2C ADDRESS SEARCH
Found address 0x50
Found address 0x68
Found address 0x3C
I2C ADDRESS SEARCH COMPLETE
`
	addrs := ParseI2CScan(raw)
	if len(addrs) != 3 {
		t.Fatalf("want 3 addresses, got %d: %v", len(addrs), addrs)
	}
	want := []byte{0x50, 0x68, 0x3C}
	for i, w := range want {
		if addrs[i] != w {
			t.Errorf("addrs[%d] = 0x%02X, want 0x%02X", i, addrs[i], w)
		}
	}
}

func TestParseI2CScan_EmptyScan(t *testing.T) {
	raw := "I2C ADDRESS SEARCH\nI2C ADDRESS SEARCH COMPLETE\n"
	addrs := ParseI2CScan(raw)
	if len(addrs) != 0 {
		t.Fatalf("want 0 addresses, got %d", len(addrs))
	}
}

func TestParseI2CScan_PartialOutput(t *testing.T) {
	// Timeout mid-scan: only one address seen before prompt.
	raw := "I2C ADDRESS SEARCH\nFound address 0x76\n"
	addrs := ParseI2CScan(raw)
	if len(addrs) != 1 || addrs[0] != 0x76 {
		t.Fatalf("want [0x76], got %v", addrs)
	}
}

func TestParseI2CScan_CaseInsensitive(t *testing.T) {
	raw := "FOUND ADDRESS 0xAA\nfound address 0x0f\n"
	addrs := ParseI2CScan(raw)
	if len(addrs) != 2 {
		t.Fatalf("want 2, got %d: %v", len(addrs), addrs)
	}
	if addrs[0] != 0xAA || addrs[1] != 0x0F {
		t.Errorf("unexpected addresses: %v", addrs)
	}
}

// --- ParseHexBytes ---

func TestParseHexBytes_SpaceSeparated(t *testing.T) {
	// Fixture: realistic `r:16` SPI read output.
	raw := "0x00 0xFF 0xAB 0x12 0xDE 0xAD 0xBE 0xEF 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08"
	got := ParseHexBytes(raw)
	if len(got) != 16 {
		t.Fatalf("want 16 bytes, got %d: %v", len(got), got)
	}
	if got[0] != 0x00 || got[1] != 0xFF || got[2] != 0xAB {
		t.Errorf("unexpected leading bytes: %02X %02X %02X", got[0], got[1], got[2])
	}
}

func TestParseHexBytes_NewlineSeparated(t *testing.T) {
	raw := "0x00\n0xFF\n0xAB\n0x12"
	got := ParseHexBytes(raw)
	if len(got) != 4 {
		t.Fatalf("want 4 bytes, got %d", len(got))
	}
}

func TestParseHexBytes_BareHex(t *testing.T) {
	raw := "00 FF AB 12"
	got := ParseHexBytes(raw)
	if len(got) != 4 {
		t.Fatalf("want 4, got %d: %v", len(got), got)
	}
	if got[0] != 0x00 || got[1] != 0xFF {
		t.Errorf("unexpected bytes: %v", got)
	}
}

func TestParseHexBytes_MalformedSkipped(t *testing.T) {
	// Non-hex tokens mixed in are skipped.
	raw := "READ: 0xAA 0xBB DONE"
	got := ParseHexBytes(raw)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d: %v", len(got), got)
	}
}

func TestParseHexBytes_Empty(t *testing.T) {
	got := ParseHexBytes("")
	if len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
}

// --- ParseVoltages ---

func TestParseVoltages_StandardOutput(t *testing.T) {
	// Fixture: realistic `v` output from Bus Pirate 5 firmware v6.1.
	raw := `VOUT: 3.30V
VREG: 3.30V
IO0: 3.30V
IO1: 3.28V
IO2: 0.00V
IO3: 3.29V
IO4: 1.65V
IO5: 3.30V
IO6: 3.30V
IO7: 3.29V`

	m, err := ParseVoltages(raw)
	if err != nil {
		t.Fatalf("ParseVoltages: %v", err)
	}
	if len(m) != 8 {
		t.Fatalf("want 8 IO pins, got %d", len(m))
	}
	if m[0] != 3.30 {
		t.Errorf("IO0 = %v, want 3.30", m[0])
	}
	if m[4] != 1.65 {
		t.Errorf("IO4 = %v, want 1.65", m[4])
	}
	if m[2] != 0.00 {
		t.Errorf("IO2 = %v, want 0.00", m[2])
	}
}

func TestParseVoltages_EmptyReturnsError(t *testing.T) {
	_, err := ParseVoltages("VOUT: 3.30V\nVREG: 3.30V\n")
	if err == nil {
		t.Fatal("expected error for output with no IO pins, got nil")
	}
}

func TestParseVoltages_MalformedLineSkipped(t *testing.T) {
	raw := "IO0: 3.30V\nIO1: not_a_number\nIO2: 1.80V"
	m, err := ParseVoltages(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := m[1]; ok {
		t.Error("IO1 should have been skipped (malformed)")
	}
	if m[0] != 3.30 || m[2] != 1.80 {
		t.Errorf("unexpected values: %v", m)
	}
}

// --- ParseSingleVoltage ---

func TestParseSingleVoltage_IOVoltage(t *testing.T) {
	raw := "IO1 VOLTAGE: 1.65V"
	v, err := ParseSingleVoltage(raw)
	if err != nil {
		t.Fatalf("ParseSingleVoltage: %v", err)
	}
	if v != 1.65 {
		t.Errorf("got %v, want 1.65", v)
	}
}

func TestParseSingleVoltage_BareValue(t *testing.T) {
	raw := "3.30V"
	v, err := ParseSingleVoltage(raw)
	if err != nil {
		t.Fatalf("ParseSingleVoltage: %v", err)
	}
	if v != 3.30 {
		t.Errorf("got %v, want 3.30", v)
	}
}

func TestParseSingleVoltage_EmptyReturnsError(t *testing.T) {
	_, err := ParseSingleVoltage("no voltage here")
	if err == nil {
		t.Fatal("expected error for output with no voltage, got nil")
	}
}

// --- ParseVoltageTable ---

func TestParseVoltageTable_AllRails(t *testing.T) {
	raw := "VOUT: 3.30V\nVREG: 3.30V\nIO0: 3.30V\nIO7: 3.29V"
	tbl := ParseVoltageTable(raw)
	if tbl["VOUT"] != 3.30 {
		t.Errorf("VOUT = %v, want 3.30", tbl["VOUT"])
	}
	if tbl["IO0"] != 3.30 {
		t.Errorf("IO0 = %v, want 3.30", tbl["IO0"])
	}
	if tbl["IO7"] != 3.29 {
		t.Errorf("IO7 = %v, want 3.29", tbl["IO7"])
	}
}
