package iec104

import (
	"strings"
	"testing"
)

// TestDecodeIFormatInterrogation pins a canonical I-format
// general interrogation command (C_IC_NA_1, COT = act).
func TestDecodeIFormatInterrogation(t *testing.T) {
	// APCI: 0x68 + Length=0x0E (14 — 4-byte control + 10-byte
	// ASDU) + Control: NS=0x0001 → bytes 02-03 = 0x02 0x00 (NS
	// shifted left by 1 bit; low bit = 0 → I-format);
	// NR=0x0005 → bytes 04-05 = 0x0A 0x00.
	// ASDU: TI=0x64 (100 = C_IC_NA_1), VSQ=0x01 (SQ=0, n=1),
	// COT=0x06 + originator=0x00, CASDU=0x0001 LE → 01 00,
	// IO: IOA (3 bytes) 00 00 00 + QOI=0x14 (station
	// interrogation).
	in := "68 0E 02 00 0A 00 64 01 06 00 01 00 00 00 00 14"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.FrameFormat != FrameI {
		t.Errorf("frame: got %s want I", r.FrameFormat)
	}
	if r.APDULength != 14 {
		t.Errorf("apdu length: got %d want 14", r.APDULength)
	}
	if r.SendSeq == nil || *r.SendSeq != 1 {
		t.Errorf("send seq: got %v want 1", r.SendSeq)
	}
	if r.ReceiveSeq == nil || *r.ReceiveSeq != 5 {
		t.Errorf("receive seq: got %v want 5", r.ReceiveSeq)
	}
	if r.TypeID != 100 || r.TypeName != "C_IC_NA_1" {
		t.Errorf("type: got %d/%q want 100/C_IC_NA_1", r.TypeID, r.TypeName)
	}
	if r.COT != 6 || r.COTName != "act" {
		t.Errorf("cot: got %d/%q want 6/act", r.COT, r.COTName)
	}
	if r.CommonAddress != 1 {
		t.Errorf("common addr: got %d want 1", r.CommonAddress)
	}
	if r.InformationObjectsHex != "00000014" {
		t.Errorf("io hex: got %q want 00000014", r.InformationObjectsHex)
	}
}

// TestDecodeIFormatMeasuredValue pins an M_ME_NC_1 (short float)
// monitor-direction frame with COT = spont.
func TestDecodeIFormatMeasuredValue(t *testing.T) {
	// NS=0x0008, NR=0x0010. ASDU: TI=13, VSQ=0x01 (one element),
	// COT=3 spont, CASDU=0x000A. IOA=00 00 00 + 5 bytes IO body
	// (4-byte float + 1-byte QDS).
	in := "68 11 10 00 20 00 0D 01 03 00 0A 00 00 00 00 00 00 80 3F 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TypeName != "M_ME_NC_1" {
		t.Errorf("typeName: got %q want M_ME_NC_1", r.TypeName)
	}
	if r.COTName != "spont" {
		t.Errorf("cotName: got %q want spont", r.COTName)
	}
	if r.CommonAddress != 10 {
		t.Errorf("common addr: got %d want 10", r.CommonAddress)
	}
}

// TestDecodeSFormatSupervisory pins a pure supervisory ack.
func TestDecodeSFormatSupervisory(t *testing.T) {
	// Control byte 2 = 0x01 (S-format).
	// NR = 0x0020 → bytes 4-5 = 0x40 0x00.
	in := "68 04 01 00 40 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.FrameFormat != FrameS {
		t.Errorf("frame: got %s want S", r.FrameFormat)
	}
	if r.SendSeq != nil {
		t.Errorf("send seq: should be nil for S-format")
	}
	if r.ReceiveSeq == nil || *r.ReceiveSeq != 32 {
		t.Errorf("receive seq: got %v want 32", r.ReceiveSeq)
	}
	if r.TypeID != 0 {
		t.Errorf("typeID: should be 0 for S-format (no ASDU)")
	}
}

// TestDecodeUFormatSTARTDT pins a U-format STARTDT_act link
// control frame.
func TestDecodeUFormatSTARTDT(t *testing.T) {
	// Control byte 2 = 0x07 (U-format = 0x03 low bits + 0x04
	// STARTDT_act).
	in := "68 04 07 00 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.FrameFormat != FrameU {
		t.Errorf("frame: got %s want U", r.FrameFormat)
	}
	if !strings.Contains(r.UFunctionBits, "STARTDT_act") {
		t.Errorf("function bits: got %q want STARTDT_act", r.UFunctionBits)
	}
}

// TestDecodeUFormatTESTFR pins a TESTFR_con frame.
func TestDecodeUFormatTESTFR(t *testing.T) {
	// Control byte 2 = 0x83 (U-format + TESTFR_con bit 0x80).
	in := "68 04 83 00 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.FrameFormat != FrameU {
		t.Errorf("frame: got %s want U", r.FrameFormat)
	}
	if !strings.Contains(r.UFunctionBits, "TESTFR_con") {
		t.Errorf("function bits: got %q want TESTFR_con", r.UFunctionBits)
	}
}

// TestDecodeCOTPositiveNegativeAndTest pins the P/N + T bits in
// byte 0 of the COT.
func TestDecodeCOTPositiveNegativeAndTest(t *testing.T) {
	// COT byte = 0xC6 (bit 7 T=1 test + bit 6 P/N=1 negative
	// + cause=6 act). VSQ=0x01.
	in := "68 0E 02 00 0A 00 64 01 C6 00 01 00 00 00 00 14"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.COT != 6 || r.COTName != "act" {
		t.Errorf("cot: got %d/%q want 6/act", r.COT, r.COTName)
	}
	if !r.COTNegativeConfirm {
		t.Errorf("COTNegativeConfirm: got false want true")
	}
	if !r.COTTest {
		t.Errorf("COTTest: got false want true")
	}
}

// TestTypeNameTable spot-checks the catalogued type IDs.
func TestTypeNameTable(t *testing.T) {
	cases := map[int]string{
		1: "M_SP_NA_1", 9: "M_ME_NA_1", 13: "M_ME_NC_1",
		45: "C_SC_NA_1", 46: "C_DC_NA_1", 100: "C_IC_NA_1",
		103: "C_CS_NA_1", 107: "C_TS_TA_1", 125: "F_SG_NA_1",
	}
	for k, v := range cases {
		if got := typeName(k); got != v {
			t.Errorf("typeName(%d) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(typeName(200), "uncatalogued") {
		t.Errorf("typeName(200) should mark uncatalogued")
	}
}

// TestCOTNameTable spot-checks every catalogued cause.
func TestCOTNameTable(t *testing.T) {
	cases := map[int]string{
		1: "per/cyc", 3: "spont", 6: "act", 7: "actcon",
		10: "actterm", 20: "inrogen", 37: "reqcogen",
		44: "unknown_type", 47: "unknown_ioa",
	}
	for k, v := range cases {
		if got := cotName(k); got != v {
			t.Errorf("cotName(%d) = %q want %q", k, got, v)
		}
	}
}

// TestUFunctionBitNamesAllSet asserts every U-format bit
// surfaces (degenerate but useful for catalogue coverage).
func TestUFunctionBitNamesAllSet(t *testing.T) {
	got := uFunctionBitNames(0xFC)
	for _, want := range []string{
		"STARTDT_act", "STARTDT_con", "STOPDT_act",
		"STOPDT_con", "TESTFR_act", "TESTFR_con",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecodeRejectsOddNibbles(t *testing.T) {
	if _, err := Decode("ABC"); err == nil {
		t.Fatal("want error for odd-length input")
	}
}

func TestDecodeRejectsShortAPCI(t *testing.T) {
	if _, err := Decode("68 04"); err == nil {
		t.Fatal("want error for short APCI")
	}
}

func TestDecodeRejectsMissingSync(t *testing.T) {
	if _, err := Decode("69 04 01 00 40 00"); err == nil {
		t.Fatal("want error when sync byte 0x68 missing")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 5)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
