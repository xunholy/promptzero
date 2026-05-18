package iso7816

import (
	"strings"
	"testing"
)

// TestDecode_BasicT0Only pins the simplest possible ATR — just
// TS + T0 with no interface bytes or historicals.
//
//	TS=3B (direct), T0=00 → Y1=0 (no interface bytes), K=0
func TestDecode_BasicT0Only(t *testing.T) {
	got, err := Decode("3B 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Convention != ConventionDirect {
		t.Errorf("Convention = %q; want 'direct'", got.Convention)
	}
	if got.HistoricalBytesCount != 0 {
		t.Errorf("HistoricalBytesCount = %d; want 0", got.HistoricalBytesCount)
	}
	if len(got.InterfaceBytes) != 0 {
		t.Errorf("InterfaceBytes = %v; want empty", got.InterfaceBytes)
	}
}

// TestDecode_RejectInvalidTS rejects a TS byte that's neither
// 0x3B nor 0x3F.
func TestDecode_RejectInvalidTS(t *testing.T) {
	_, err := Decode("FF 00")
	if err == nil {
		t.Fatal("want error for invalid TS")
	}
	if !strings.Contains(err.Error(), "TS") {
		t.Errorf("err = %v; want 'TS' wording", err)
	}
}

// TestDecode_InverseConvention recognises TS = 0x3F.
func TestDecode_InverseConvention(t *testing.T) {
	got, err := Decode("3F 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Convention != ConventionInverse {
		t.Errorf("Convention = %q; want 'inverse'", got.Convention)
	}
}

// TestDecode_HistoricalsOnly — ATR with K=4 historicals and no
// interface bytes:
//
//	3B 04 'NXP1' (4 historical bytes)
func TestDecode_HistoricalsOnly(t *testing.T) {
	got, err := Decode("3B 04 4E 58 50 31")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.HistoricalBytesCount != 4 {
		t.Errorf("HistoricalBytesCount = %d; want 4", got.HistoricalBytesCount)
	}
	if got.HistoricalBytesHex != "4E585031" {
		t.Errorf("HistoricalBytesHex = %q", got.HistoricalBytesHex)
	}
	if got.HistoricalASCII != "NXP1" {
		t.Errorf("HistoricalASCII = %q; want 'NXP1'", got.HistoricalASCII)
	}
}

// TestDecode_TA1WithFiDi pins TA1 decode — the clock conversion
// factor Fi and work etu factor Di. TA1 = 0x96 means Fi=9
// (512), Di=6 (32).
//
//	3B 10 96 — Y1=1 (TA1 present), K=0, TA1=0x96
func TestDecode_TA1WithFiDi(t *testing.T) {
	got, err := Decode("3B 10 96")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.InterfaceBytes) != 1 {
		t.Fatalf("InterfaceBytes count = %d; want 1", len(got.InterfaceBytes))
	}
	ib := got.InterfaceBytes[0]
	if ib.Kind != "TA" {
		t.Errorf("Kind = %q; want 'TA'", ib.Kind)
	}
	if ib.Decoded["fi"] != 9 {
		t.Errorf("Fi = %v; want 9", ib.Decoded["fi"])
	}
	if ib.Decoded["fi_value"] != 512 {
		t.Errorf("Fi value = %v; want 512", ib.Decoded["fi_value"])
	}
	if ib.Decoded["di"] != 6 {
		t.Errorf("Di = %v; want 6", ib.Decoded["di"])
	}
	if ib.Decoded["di_value"] != 32 {
		t.Errorf("Di value = %v; want 32", ib.Decoded["di_value"])
	}
}

// TestDecode_TDChain pins a two-round interface-byte chain
// announcing T=1 protocol.
//
//	3B 80 80 01 00
//	  TS=3B, T0=0x80 (Y1=8 → TD1 present, K=0)
//	  TD1=0x80 (next Y=8 → TD2 present, T=0)
//	  TD2=0x01 (next Y=0 → done, T=1)
//	  TCK = 80 XOR 80 XOR 01 = 01 ✓
func TestDecode_TDChain(t *testing.T) {
	got, err := Decode("3B 80 80 01 01")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.InterfaceBytes) != 2 {
		t.Fatalf("InterfaceBytes count = %d; want 2", len(got.InterfaceBytes))
	}
	if got.InterfaceBytes[0].Kind != "TD" || got.InterfaceBytes[1].Kind != "TD" {
		t.Errorf("Kinds = %q,%q; want TD,TD",
			got.InterfaceBytes[0].Kind, got.InterfaceBytes[1].Kind)
	}
	// Both T=0 and T=1 announced.
	if len(got.ProtocolsAnnounced) != 2 ||
		got.ProtocolsAnnounced[0] != 0 || got.ProtocolsAnnounced[1] != 1 {
		t.Errorf("ProtocolsAnnounced = %v; want [0 1]", got.ProtocolsAnnounced)
	}
	if !got.TCKValid {
		t.Errorf("TCKValid = false; want true (computed 0x%X, got 0x%X)",
			got.TCKExpected, *got.TCK)
	}
}

// TestDecode_TCKMissingWhenRequired errors out when a non-T=0
// protocol is announced but no TCK byte is present.
func TestDecode_TCKMissingWhenRequired(t *testing.T) {
	// 3B 80 01 — TS, T0=0x80 (Y1=8 → TD1 present), TD1=0x01
	// (T=1, no next round). TCK required but absent.
	_, err := Decode("3B 80 01")
	if err == nil {
		t.Fatal("want error when TCK is required but missing")
	}
	if !strings.Contains(err.Error(), "TCK") {
		t.Errorf("err = %v", err)
	}
}

// TestDecode_TCKInvalid surfaces TCKValid=false when the check
// byte doesn't match the XOR.
func TestDecode_TCKInvalid(t *testing.T) {
	// Same as TDChain but with TCK=0xAA instead of 0x01.
	got, err := Decode("3B 80 80 01 AA")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.TCKValid {
		t.Error("TCKValid = true; want false for mismatched TCK")
	}
	if got.TCKExpected != 0x01 {
		t.Errorf("TCKExpected = 0x%02X; want 0x01", got.TCKExpected)
	}
}

// TestDecode_T0OnlyNoTCK — when only T=0 is implied, TCK is
// optional. ATR like "3B 00" should decode without TCK
// validation issues.
func TestDecode_T0OnlyNoTCK(t *testing.T) {
	got, err := Decode("3B 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.TCK != nil {
		t.Errorf("TCK = %v; want nil for T=0-only ATR with no TCK byte", got.TCK)
	}
}

// TestDecode_CategoryIndicator surfaces the historical-byte
// Category Indicator name for the common 0x80 (compact-TLV)
// kick-off byte.
func TestDecode_CategoryIndicator(t *testing.T) {
	got, err := Decode("3B 03 80 AA BB")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(got.HistoricalCategoryIndicator, "Compact-TLV") {
		t.Errorf("Category Indicator = %q; want it to mention Compact-TLV",
			got.HistoricalCategoryIndicator)
	}
}

// TestDecode_RealEMVCardATR pins decoding of a typical EMV
// payment card ATR. Picked a representative ATR shape:
//
//	3B 6E 00 00 80 31 80 66 B0 84 0C 01 6E 01 83 00 90 00
//
// TS=3B, T0=0x6E (Y1=6 → TB1+TC1 present, K=14), TB1=0x00,
// TC1=0x00, then 14 historical bytes (Visa/Mastercard-style
// IIN + AID prefix). No TD chain → only T=0 → TCK optional;
// the 14 historicals + no TCK pads out to len 17. Just verify
// the structural decode passes.
func TestDecode_RealEMVCardATR(t *testing.T) {
	got, err := Decode("3B 6E 00 00 80 31 80 66 B0 84 0C 01 6E 01 83 00 90 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.HistoricalBytesCount != 14 {
		t.Errorf("HistoricalBytesCount = %d; want 14", got.HistoricalBytesCount)
	}
	if len(got.InterfaceBytes) != 2 {
		t.Errorf("InterfaceBytes count = %d; want 2 (TB1 + TC1)",
			len(got.InterfaceBytes))
	}
	// Only T=0 → no TCK expected
	if len(got.ProtocolsAnnounced) != 0 {
		t.Errorf("ProtocolsAnnounced = %v; want empty (no TD chain)",
			got.ProtocolsAnnounced)
	}
}

// TestDecode_TooShort — input shorter than 2 bytes is rejected.
func TestDecode_TooShort(t *testing.T) {
	if _, err := Decode("3B"); err == nil {
		t.Error("1-byte input: want error")
	}
}

// TestDecode_TruncatedInterfaceByte — T0 declares interface
// bytes that aren't in the buffer.
func TestDecode_TruncatedInterfaceByte(t *testing.T) {
	// T0=0xF0 (Y1=F → TA1+TB1+TC1+TD1 all present, K=0), but
	// no interface bytes follow.
	_, err := Decode("3B F0")
	if err == nil {
		t.Fatal("want error for missing interface bytes")
	}
}

// TestDecode_BadInput — input validation.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecode_ToleratesSeparators — ':' / '-' / '_' / whitespace.
func TestDecode_ToleratesSeparators(t *testing.T) {
	for _, in := range []string{
		"3B:04:4E:58:50:31",
		"3B-04-4E-58-50-31",
		"  3B 04 4E 58 50 31  ",
	} {
		got, err := Decode(in)
		if err != nil {
			t.Errorf("Decode(%q): %v", in, err)
			continue
		}
		if got.HistoricalASCII != "NXP1" {
			t.Errorf("Decode(%q): HistoricalASCII = %q", in, got.HistoricalASCII)
		}
	}
}

// TestFiDiTables spot-checks a handful of Fi/Di table entries
// against the published ISO 7816-3 values.
func TestFiDiTables(t *testing.T) {
	if fiTable[0x1] != 372 {
		t.Errorf("fiTable[1] = %d; want 372", fiTable[0x1])
	}
	if fiTable[0x9] != 512 {
		t.Errorf("fiTable[9] = %d; want 512", fiTable[0x9])
	}
	if diTable[0x1] != 1 {
		t.Errorf("diTable[1] = %d; want 1", diTable[0x1])
	}
	if diTable[0x6] != 32 {
		t.Errorf("diTable[6] = %d; want 32", diTable[0x6])
	}
}
