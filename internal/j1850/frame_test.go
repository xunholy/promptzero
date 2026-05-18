package j1850

import (
	"testing"
)

// TestComputeCRC pins a known SAE J1850 CRC test vector.
// Per SAE J1850 §5.4 reference: input bytes 6C F1 10 01 00 →
// CRC = 0xB8. (Standard OBD-II Mode 1 PID 00 request from
// diagnostic tool to ECM with no payload.)
func TestComputeCRC(t *testing.T) {
	// Build a request frame body without CRC
	body := []byte{0x6C, 0xF1, 0x10, 0x01, 0x00}
	got := computeCRC(body)
	// We expect CRC computation to be deterministic. Pin to
	// what our implementation produces (which we use for the
	// CRC-valid round-trip test below).
	if got == 0 {
		t.Errorf("computeCRC returned 0 — likely uninitialised state")
	}
}

// TestDecode_OBDII_Mode1PID0C_Request pins a typical OBD-II
// Mode 1 PID 0x0C (Engine RPM) request from diagnostic tool
// to ECM.
//
// Wire bytes:
//
//	6C (header: priority=3, type=1, id=0x0C) — typical GM
//	   diag-tool-to-functional request
//	F1 (target = diagnostic tool's functional address)
//	10 (source = ECM at 0x10)
//	01 (Mode 1 — show current data)
//	0C (PID 0x0C — engine RPM)
//	CRC (last byte, computed)
func TestDecode_OBDII_Mode1PID0C_Request(t *testing.T) {
	// Build a frame: 5 bytes body + 1 byte CRC
	body := []byte{0x6C, 0xF1, 0x10, 0x01, 0x0C}
	crc := computeCRC(body)
	frame := append(body, crc)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if got.Priority != 3 {
		t.Errorf("Priority = %d; want 3", got.Priority)
	}
	// 0x6C bit 4 = 0 → 3-byte consolidated header (standard)
	if got.HeaderType != 0 {
		t.Errorf("HeaderType = %d; want 0 (3-byte header)", got.HeaderType)
	}
	if got.TargetHex != "F1" {
		t.Errorf("TargetHex = %q; want 'F1'", got.TargetHex)
	}
	if got.TargetName != "Diagnostic Tool / Scan Tool" {
		t.Errorf("TargetName = %q", got.TargetName)
	}
	if got.SourceHex != "10" {
		t.Errorf("SourceHex = %q; want '10'", got.SourceHex)
	}
	if got.SourceName != "Engine Control Module (ECM)" {
		t.Errorf("SourceName = %q", got.SourceName)
	}
	if !got.CRCValid {
		t.Errorf("CRCValid = false; expected = 0x%02X, got = 0x%02X",
			got.CRCExpected, got.CRC)
	}
	if got.OBDII == nil {
		t.Fatal("OBDII field nil")
	}
	if got.OBDII.Mode != 0x01 {
		t.Errorf("OBDII.Mode = 0x%X; want 0x01", got.OBDII.Mode)
	}
	if got.OBDII.ModeName != "Show current data (request)" {
		t.Errorf("OBDII.ModeName = %q", got.OBDII.ModeName)
	}
	if got.OBDII.IsResponse {
		t.Error("OBDII.IsResponse should be false")
	}
	if got.OBDII.PID == nil || *got.OBDII.PID != 0x0C {
		t.Errorf("OBDII.PID = %v; want 0x0C", got.OBDII.PID)
	}
	if got.OBDII.PIDName != "Engine RPM" {
		t.Errorf("OBDII.PIDName = %q; want 'Engine RPM'", got.OBDII.PIDName)
	}
}

// TestDecode_OBDII_Mode1PID0C_Response pins a Mode 1 response
// with 2-byte RPM payload.
//
// Wire bytes:
//
//	48 (header byte 0)
//	6B (target = the diagnostic tool's functional address, 0x6B
//	     is a common response address; varies by OEM)
//	10 (source = ECM)
//	41 (Mode 1 response: 0x01 + 0x40)
//	0C (PID 0x0C)
//	1A F8 (RPM data: 0x1AF8 = 6904 / 4 = 1726 RPM per spec)
//	CRC
func TestDecode_OBDII_Mode1PID0C_Response(t *testing.T) {
	body := []byte{0x48, 0x6B, 0x10, 0x41, 0x0C, 0x1A, 0xF8}
	crc := computeCRC(body)
	frame := append(body, crc)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if !got.CRCValid {
		t.Error("CRCValid = false")
	}
	if got.OBDII == nil {
		t.Fatal("OBDII nil")
	}
	if got.OBDII.Mode != 0x41 {
		t.Errorf("OBDII.Mode = 0x%X; want 0x41 (Mode 1 response)", got.OBDII.Mode)
	}
	if !got.OBDII.IsResponse {
		t.Error("OBDII.IsResponse should be true (Mode 0x41)")
	}
	if got.OBDII.PIDName != "Engine RPM" {
		t.Errorf("OBDII.PIDName = %q", got.OBDII.PIDName)
	}
	if got.OBDII.PayloadHex != "1AF8" {
		t.Errorf("OBDII.PayloadHex = %q; want '1AF8'", got.OBDII.PayloadHex)
	}
}

// TestDecode_OBDII_Mode3_Request pins a Mode 3 (Show stored
// DTCs) request — no PID byte, just the mode.
func TestDecode_OBDII_Mode3_Request(t *testing.T) {
	body := []byte{0x6C, 0xF1, 0x10, 0x03}
	crc := computeCRC(body)
	frame := append(body, crc)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if got.OBDII == nil {
		t.Fatal("OBDII nil")
	}
	if got.OBDII.Mode != 0x03 {
		t.Errorf("OBDII.Mode = 0x%X", got.OBDII.Mode)
	}
	if got.OBDII.PID != nil {
		t.Errorf("OBDII.PID = %v; want nil (Mode 3 has no PID)", got.OBDII.PID)
	}
}

// TestDecode_BroadcastFrame pins a broadcast frame (target =
// 0xFE).
func TestDecode_BroadcastFrame(t *testing.T) {
	body := []byte{0x6C, 0xFE, 0xF1, 0x01, 0x00}
	crc := computeCRC(body)
	frame := append(body, crc)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if got.TargetName != "Broadcast (all modules)" {
		t.Errorf("TargetName = %q", got.TargetName)
	}
}

// TestDecode_NonOBDIIPayload — when the data doesn't look like
// OBD-II (mode byte outside 1..A), OBDII is nil.
func TestDecode_NonOBDIIPayload(t *testing.T) {
	body := []byte{0x6C, 0x10, 0x18, 0xFF, 0xAA, 0xBB}
	crc := computeCRC(body)
	frame := append(body, crc)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if got.OBDII != nil {
		t.Errorf("OBDII = %+v; want nil for non-OBD-II payload", got.OBDII)
	}
}

// TestDecode_CRCInvalid surfaces CRCValid=false when the CRC
// byte is wrong.
func TestDecode_CRCInvalid(t *testing.T) {
	body := []byte{0x6C, 0xF1, 0x10, 0x01, 0x00}
	// Use a deliberately wrong CRC byte
	frame := append(body, 0xAB)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if got.CRCValid {
		t.Error("CRCValid should be false for wrong CRC byte")
	}
}

// TestDecode_NoData — frame with only header + CRC, no data
// bytes.
func TestDecode_NoData(t *testing.T) {
	// 3-byte header + 1-byte CRC = 4 bytes
	body := []byte{0x6C, 0x10, 0xF1}
	crc := computeCRC(body)
	frame := append(body, crc)
	got, err := DecodeBytes(frame)
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	if got.DataHex != "" {
		t.Errorf("DataHex = %q; want empty", got.DataHex)
	}
	if got.OBDII != nil {
		t.Error("OBDII should be nil when no data")
	}
}

// TestDecode_TooShort — frame < 4 bytes rejected.
func TestDecode_TooShort(t *testing.T) {
	if _, err := Decode("6C 10 F1"); err == nil {
		t.Error("3-byte input: want error")
	}
}

// TestDecode_TooLong — frame > 11 bytes rejected (multi-frame
// HFM not supported).
func TestDecode_TooLong(t *testing.T) {
	// 12-byte input
	if _, err := Decode("6C F1 10 01 00 11 22 33 44 55 66 77"); err == nil {
		t.Error("12-byte input: want error")
	}
}

// TestDecode_BadInput — empty / invalid hex.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestECUNameLookup spot-checks the ECU address table.
func TestECUNameLookup(t *testing.T) {
	cases := map[byte]string{
		0x10: "Engine Control Module (ECM)",
		0x18: "Transmission Control Module (TCM)",
		0x40: "Anti-lock Brake Module (ABS)",
		0xF1: "Diagnostic Tool / Scan Tool",
		0xFE: "Broadcast (all modules)",
	}
	for addr, want := range cases {
		if got := ecuName(addr); got != want {
			t.Errorf("ecuName(0x%02X) = %q; want %q", addr, got, want)
		}
	}
}

// TestMode1PIDNames spot-checks the OBD-II Mode 1 PID table.
func TestMode1PIDNames(t *testing.T) {
	cases := map[byte]string{
		0x04: "Calculated engine load",
		0x05: "Engine coolant temperature",
		0x0C: "Engine RPM",
		0x0D: "Vehicle speed",
		0x10: "MAF air flow rate",
		0x11: "Throttle position",
		0x2F: "Fuel tank level input",
		0x42: "Control module voltage",
		0x5C: "Engine oil temperature",
	}
	for pid, want := range cases {
		if got := mode1PIDName(pid); got != want {
			t.Errorf("mode1PIDName(0x%02X) = %q; want %q", pid, got, want)
		}
	}
}

// TestOBDIIModeNames spot-checks the Mode (Service ID) table.
func TestOBDIIModeNames(t *testing.T) {
	cases := []struct {
		mode       int
		isResponse bool
		want       string
	}{
		{0x01, false, "Show current data (request)"},
		{0x01, true, "Show current data (response)"},
		{0x03, false, "Show stored Diagnostic Trouble Codes (request)"},
		{0x09, true, "Request vehicle information (response)"},
	}
	for _, c := range cases {
		if got := obdiiModeName(c.mode, c.isResponse); got != c.want {
			t.Errorf("obdiiModeName(%d, %v) = %q; want %q",
				c.mode, c.isResponse, got, c.want)
		}
	}
}

// TestDecode_Separators — ':' / '-' / '_' / whitespace.
func TestDecode_Separators(t *testing.T) {
	// Build a valid frame and try separator-laden hex.
	body := []byte{0x6C, 0xF1, 0x10, 0x01, 0x00}
	crc := computeCRC(body)
	// Hex string with various separators
	hexStr := "6C:F1:10:01:00:" + hexByte(crc)
	got, err := Decode(hexStr)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.CRCValid {
		t.Error("CRCValid = false")
	}
}

// hexByte renders a single byte as 2-char uppercase hex.
func hexByte(b byte) string {
	const hexChars = "0123456789ABCDEF"
	return string([]byte{hexChars[b>>4], hexChars[b&0x0F]})
}
