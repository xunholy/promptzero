package nrf24

import (
	"strings"
	"testing"
)

// TestDecode_MinimalPacket pins a minimal NRF24 ESB packet:
//
//	Address (5 bytes): AA BB CC DD EE
//	PCF byte: 0x10 = PayloadLen 4 (bits 7..2 = 000100), PID 0
//	Payload (4 bytes): 01 02 03 04
//	CRC (2 bytes): 55 66
func TestDecode_MinimalPacket(t *testing.T) {
	got, err := Decode("AA BB CC DD EE 10 01 02 03 04 55 66", DecodeOptions{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.AddressHex != "AABBCCDDEE" {
		t.Errorf("AddressHex = %q; want 'AABBCCDDEE'", got.AddressHex)
	}
	if got.PCF.PayloadLength != 4 {
		t.Errorf("PayloadLength = %d; want 4", got.PCF.PayloadLength)
	}
	if got.PCF.PID != 0 {
		t.Errorf("PID = %d; want 0", got.PCF.PID)
	}
	if got.PayloadHex != "01020304" {
		t.Errorf("PayloadHex = %q; want '01020304'", got.PayloadHex)
	}
	if got.CRCHex != "5566" {
		t.Errorf("CRCHex = %q; want '5566'", got.CRCHex)
	}
}

// TestDecode_PCFBitFields exercises every PCF field — payload
// length spans bits 7..2, PID is bits 1..0.
//
// PCF 0xFF = PayloadLen 63 (bits 7..2 = 111111), PID 3
// (bits 1..0 = 11). PayloadLen 63 > 32 max, but we still parse
// the field and let the operator notice; the buffer-length
// check catches it via the payload-truncation error.
func TestDecode_PCFBitFields(t *testing.T) {
	// PayloadLen 5 (binary 000101), PID 2 (binary 10) → PCF = 00010110 = 0x16
	got, err := Decode("AA BB CC DD EE 16 01 02 03 04 05 99 AA", DecodeOptions{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.PCF.PayloadLength != 5 {
		t.Errorf("PayloadLength = %d; want 5", got.PCF.PayloadLength)
	}
	if got.PCF.PID != 2 {
		t.Errorf("PID = %d; want 2", got.PCF.PID)
	}
}

// TestDecode_ShortAddress exercises the 3-byte address path.
func TestDecode_ShortAddress(t *testing.T) {
	// Address (3): AA BB CC
	// PCF 0x08 = PayloadLen 2, PID 0
	// Payload: 01 02
	// CRC (2): FF EE
	got, err := Decode("AA BB CC 08 01 02 FF EE", DecodeOptions{AddressLength: 3})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.AddressHex != "AABBCC" {
		t.Errorf("AddressHex = %q; want 'AABBCC'", got.AddressHex)
	}
	if got.AddressLength != 3 {
		t.Errorf("AddressLength = %d; want 3", got.AddressLength)
	}
}

// TestDecode_OneByteCRC exercises the 1-byte CRC path.
func TestDecode_OneByteCRC(t *testing.T) {
	// Address (5) + PCF 0x08 (PayloadLen 2) + Payload (2) + CRC (1)
	got, err := Decode("AA BB CC DD EE 08 01 02 99", DecodeOptions{CRCLength: 1})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.CRCLength != 1 {
		t.Errorf("CRCLength = %d; want 1", got.CRCLength)
	}
	if got.CRCHex != "99" {
		t.Errorf("CRCHex = %q; want '99'", got.CRCHex)
	}
}

// TestDecode_LogitechHIDReport pins recognition of a Logitech
// Unifying HID Boot Keyboard report (report type 0x40):
//
//	Address (5): AA BB CC DD EE
//	PCF 0x1C = PayloadLen 7, PID 0
//	Payload: 01 40 02 00 00 04 00 (device_index=1, report=0x40 HID,
//	         then modifier+reserved+key 0x04='a')
//	CRC: 12 34
func TestDecode_LogitechHIDReport(t *testing.T) {
	got, err := Decode("AA BB CC DD EE 1C 01 40 02 00 00 04 00 12 34", DecodeOptions{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Logitech == nil {
		t.Fatal("Logitech report not recognised")
	}
	if got.Logitech.DeviceIndex != 1 {
		t.Errorf("DeviceIndex = %d; want 1", got.Logitech.DeviceIndex)
	}
	if got.Logitech.ReportType != 0x40 {
		t.Errorf("ReportType = 0x%X; want 0x40", got.Logitech.ReportType)
	}
	if got.Logitech.ReportName != "HID Boot Keyboard report" {
		t.Errorf("ReportName = %q", got.Logitech.ReportName)
	}
	if got.Logitech.BodyHex != "0200000400" {
		t.Errorf("BodyHex = %q; want '0200000400'", got.Logitech.BodyHex)
	}
}

// TestDecode_LogitechEncryptedKeyboard pins report type 0x4F.
func TestDecode_LogitechEncryptedKeyboard(t *testing.T) {
	// Address (5) + PCF 0x28 (PayloadLen 10) + Payload (10 bytes:
	// device_index 02 + report 4F + 8 encrypted bytes) + CRC (2)
	got, err := Decode("AA BB CC DD EE 28 02 4F AA BB CC DD EE FF 00 11 12 34", DecodeOptions{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Logitech == nil {
		t.Fatal("Logitech report not recognised")
	}
	if got.Logitech.ReportName != "Encrypted keyboard report" {
		t.Errorf("ReportName = %q", got.Logitech.ReportName)
	}
}

// TestDecode_LogitechMouseReport pins report type 0x4D (mouse).
func TestDecode_LogitechMouseReport(t *testing.T) {
	// Address + PCF 0x1C (PayloadLen 7) + Payload (device_index 03 +
	// report 4D + 5-byte mouse body) + CRC
	got, err := Decode("AA BB CC DD EE 1C 03 4D 00 01 02 03 04 12 34", DecodeOptions{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Logitech.ReportName != "Mouse movement report" {
		t.Errorf("ReportName = %q", got.Logitech.ReportName)
	}
}

// TestDecode_UnknownLogitechReportNotSurfaced — when payload[1]
// isn't in the Logitech table, the Logitech field stays nil.
func TestDecode_UnknownLogitechReportNotSurfaced(t *testing.T) {
	// Payload: device_index 01 + unknown report 0xAB + body
	got, err := Decode("AA BB CC DD EE 10 01 AB 00 00 12 34", DecodeOptions{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Logitech != nil {
		t.Errorf("Logitech should be nil for unknown report type; got %+v",
			got.Logitech)
	}
}

// TestDecode_TruncatedPayload — PCF declares a payload length
// longer than the buffer holds.
func TestDecode_TruncatedPayload(t *testing.T) {
	// PCF 0x80 = PayloadLen 32 (binary 100000), PID 0
	// But only a few bytes follow.
	_, err := Decode("AA BB CC DD EE 80 01 02 03", DecodeOptions{})
	if err == nil {
		t.Fatal("want error for over-declared payload length")
	}
}

// TestDecode_InvalidAddressLength — only 3/4/5 are valid.
func TestDecode_InvalidAddressLength(t *testing.T) {
	cases := []int{0, 1, 2, 6, 10}
	for _, l := range cases {
		// Provide enough bytes so the length check itself triggers,
		// not the buffer-too-short check.
		_, err := Decode(strings.Repeat("AA", 20), DecodeOptions{AddressLength: l})
		// 0 is interpreted as "default 5" — should succeed.
		if l == 0 {
			continue
		}
		if err == nil {
			t.Errorf("AddressLength=%d: want error", l)
		}
	}
}

// TestDecode_InvalidCRCLength — only 1/2 are valid.
func TestDecode_InvalidCRCLength(t *testing.T) {
	_, err := Decode("AA BB CC DD EE 04 01 02 03", DecodeOptions{CRCLength: 3})
	if err == nil {
		t.Fatal("want error for invalid CRC length")
	}
}

// TestDecode_TooShort — buffer smaller than addr + PCF + CRC.
func TestDecode_TooShort(t *testing.T) {
	_, err := Decode("AA BB CC DD EE 04", DecodeOptions{})
	if err == nil {
		t.Fatal("want error for buffer too short for minimum frame")
	}
}

// TestDecode_BadInput — empty / invalid hex.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode("", DecodeOptions{}); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Decode("ZZ", DecodeOptions{}); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecode_ToleratesSeparators — ':' / '-' / '_' / whitespace.
func TestDecode_ToleratesSeparators(t *testing.T) {
	base := "AA BB CC DD EE 10 01 02 03 04 55 66"
	for _, sep := range []string{":", "-", "_", " "} {
		in := strings.ReplaceAll(base, " ", sep)
		got, err := Decode(in, DecodeOptions{})
		if err != nil {
			t.Errorf("sep=%q: %v", sep, err)
			continue
		}
		if got.AddressHex != "AABBCCDDEE" {
			t.Errorf("sep=%q: AddressHex = %q", sep, got.AddressHex)
		}
	}
}

// TestLogitechReportTypeNames spot-checks the Logitech report-
// type catalog.
func TestLogitechReportTypeNames(t *testing.T) {
	cases := map[byte]string{
		0x40: "HID Boot Keyboard report",
		0x4D: "Mouse movement report",
		0x4F: "Encrypted keyboard report",
		0xC2: "Plaintext keyboard report (legacy)",
	}
	for code, want := range cases {
		if got := logitechReportTypes[code]; got != want {
			t.Errorf("logitechReportTypes[0x%02X] = %q; want %q",
				code, got, want)
		}
	}
}
