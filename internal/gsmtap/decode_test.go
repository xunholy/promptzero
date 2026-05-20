package gsmtap

import (
	"strings"
	"testing"
)

// TestDecodeGSMUmL2BCCH pins a canonical GSMTAP-wrapped GSM Um
// L2 frame on the BCCH (Broadcast Control Channel) — the
// first thing every grgsm_livemon capture sees.
func TestDecodeGSMUmL2BCCH(t *testing.T) {
	// Version 2, HeaderLen 4 (16 bytes), PayloadType 1
	// (UM_L2), Timeslot 0, ARFCN = 121 (= 0x0079, downlink,
	// no PCS), Signal = -70 dBm (0xBA = -70 int8), SNR = 25
	// (0x19 int8), Frame = 0x000A0BCD, SubType 1 BCCH,
	// Antenna 0, SubSlot 0, Reserved 0.
	// Then a 23-byte BCCH frame payload (canonical
	// FILL_NORMAL frame: 0x2B padding).
	in := "02 04 01 00 0079 BA 19 000A0BCD 01 00 00 00 " +
		"2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Version != 2 {
		t.Errorf("version: got %d want 2", r.Version)
	}
	if r.PayloadName != "UM_L2" {
		t.Errorf("payloadType: got %q want UM_L2", r.PayloadName)
	}
	if r.ARFCN != 121 {
		t.Errorf("arfcn: got %d want 121", r.ARFCN)
	}
	if r.ARFCNUplink {
		t.Errorf("ARFCNUplink: should be false")
	}
	if r.ARFCNPCSBand {
		t.Errorf("ARFCNPCSBand: should be false")
	}
	if r.SignalDBm != -70 {
		t.Errorf("signal: got %d want -70", r.SignalDBm)
	}
	if r.SNRDb != 25 {
		t.Errorf("snr: got %d want 25", r.SNRDb)
	}
	if r.FrameNumber != 0x000A0BCD {
		t.Errorf("frame number: got 0x%X want 0xA0BCD", r.FrameNumber)
	}
	if r.SubTypeName != "BCCH" {
		t.Errorf("subType: got %q want BCCH", r.SubTypeName)
	}
	if !strings.HasPrefix(r.PayloadHex, "2B2B2B2B") {
		t.Errorf("payload: got %q", r.PayloadHex)
	}
}

// TestDecodeUplinkPCSBand pins ARFCN uplink + PCS-band bit
// extraction.
func TestDecodeUplinkPCSBand(t *testing.T) {
	// ARFCN field = 0xC050 (uplink bit 0x8000 + PCS bit
	// 0x4000 + ARFCN 80). PayloadType 1, SubType 3 RACH
	// (canonical uplink channel).
	in := "02 04 01 00 C050 BA 19 000A0BCD 03 00 00 00 AABBCC"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ARFCN != 80 {
		t.Errorf("arfcn: got %d want 80", r.ARFCN)
	}
	if !r.ARFCNUplink {
		t.Errorf("ARFCNUplink: should be true")
	}
	if !r.ARFCNPCSBand {
		t.Errorf("ARFCNPCSBand: should be true")
	}
	if r.SubTypeName != "RACH" {
		t.Errorf("subType: got %q want RACH", r.SubTypeName)
	}
}

// TestDecodeSDCCH8 pins SDCCH/8 — the common signalling channel
// for call setup + SMS delivery.
func TestDecodeSDCCH8(t *testing.T) {
	// SubType 8 SDCCH8; SubSlot 3 (one of 8 sub-slots).
	in := "02 04 01 00 0079 BA 19 000A0BCD 08 00 03 00 00112233"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.SubTypeName != "SDCCH8" {
		t.Errorf("subType: got %q want SDCCH8", r.SubTypeName)
	}
	if r.SubSlot != 3 {
		t.Errorf("subSlot: got %d want 3", r.SubSlot)
	}
}

// TestDecodeLTERRC pins LTE RRC payload type with downlink
// direction.
func TestDecodeLTERRC(t *testing.T) {
	// PayloadType 0x0E LTE_RRC; SubType 0 (DL channel).
	in := "02 04 0E 00 0000 00 00 00000001 00 00 00 00 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.PayloadName != "LTE_RRC" {
		t.Errorf("payloadType: got %q want LTE_RRC", r.PayloadName)
	}
	if r.SubTypeName != "Downlink" {
		t.Errorf("subType: got %q want Downlink", r.SubTypeName)
	}
}

// TestDecodeSIMAPDU pins SubType 4 SIM (APDU exchange — used
// for SIM-card pentest captures).
func TestDecodeSIMAPDU(t *testing.T) {
	in := "02 04 04 00 0000 00 00 00000001 00 00 00 00 80A40000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.PayloadName != "SIM" {
		t.Errorf("payloadType: got %q want SIM", r.PayloadName)
	}
	if r.PayloadHex != "80A40000" {
		t.Errorf("payload: got %q want 80A40000", r.PayloadHex)
	}
}

// TestDecodeAbisLAPD pins SubType 2 ABIS (BTS↔BSC LAPD frames).
func TestDecodeAbisLAPD(t *testing.T) {
	in := "02 04 02 00 0000 00 00 00000001 00 00 00 00 010203"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.PayloadName != "ABIS" {
		t.Errorf("payloadType: got %q want ABIS", r.PayloadName)
	}
}

// TestPayloadTypeNameTable spot-checks key catalogued payload
// types.
func TestPayloadTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0x01: "UM_L2", 0x02: "ABIS", 0x04: "SIM",
		0x0D: "UMTS_RLC_MAC", 0x0E: "LTE_RRC",
		0x0F: "LTE_MAC", 0x10: "LTE_MAC_FRAMED",
		0x11: "OSMOCORE_LOG", 0x12: "QC_DIAG",
	}
	for k, v := range cases {
		if got := payloadTypeName(k); got != v {
			t.Errorf("payloadTypeName(0x%02X) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(payloadTypeName(0xFE), "uncatalogued") {
		t.Errorf("uncatalogued payload type should be flagged")
	}
}

// TestUmL2ChannelNameTable spot-checks GSM Um L2 channel
// types.
func TestUmL2ChannelNameTable(t *testing.T) {
	cases := map[int]string{
		0x01: "BCCH", 0x02: "CCCH", 0x03: "RACH",
		0x05: "PCH", 0x06: "SDCCH", 0x08: "SDCCH8",
		0x09: "TCH_F", 0x0A: "TCH_H", 0x0D: "PDCH",
		0x10: "VOICE_F", 0x11: "VOICE_H",
	}
	for k, v := range cases {
		if got := umL2ChannelName(k); got != v {
			t.Errorf("umL2ChannelName(0x%02X) = %q want %q", k, got, v)
		}
	}
}

// TestLTERRCChannelNameTable asserts the even/odd direction
// convention.
func TestLTERRCChannelNameTable(t *testing.T) {
	if lteRRCChannelName(0) != "Downlink" {
		t.Errorf("LTE RRC 0 should be Downlink")
	}
	if lteRRCChannelName(1) != "Uplink" {
		t.Errorf("LTE RRC 1 should be Uplink")
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

func TestDecodeRejectsShortHeader(t *testing.T) {
	if _, err := Decode("02 04 01 00"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 15)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
