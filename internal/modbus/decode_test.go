package modbus

import (
	"strings"
	"testing"
)

// TestDecode_RTU_ReadHoldingRegistersRequest pins a Read
// Holding Registers request from slave 0x01: start 0x0000,
// quantity 0x0001. CRC computed by this implementation.
func TestDecode_RTU_ReadHoldingRegistersRequest(t *testing.T) {
	// Body: 01 03 00 00 00 01 → CRC wire bytes 84 0A
	got, err := Decode("01 03 00 00 00 01 84 0A")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Format != "RTU" {
		t.Errorf("Format = %q; want RTU", got.Format)
	}
	if got.UnitID != 0x01 {
		t.Errorf("UnitID = 0x%02X; want 0x01", got.UnitID)
	}
	if got.FunctionCode != 0x03 {
		t.Errorf("FunctionCode = 0x%02X; want 0x03", got.FunctionCode)
	}
	if got.FunctionName != "Read Holding Registers" {
		t.Errorf("FunctionName = %q", got.FunctionName)
	}
	if !got.CRCValid {
		t.Errorf("CRCValid = false; expected %s, got %s", got.CRCExpected, got.CRC)
	}
	if got.Request == nil {
		t.Fatal("Request nil for read request shape")
	}
	if got.Request.StartAddress == nil || *got.Request.StartAddress != 0 {
		t.Errorf("StartAddress = %v; want 0", got.Request.StartAddress)
	}
	if got.Request.Quantity == nil || *got.Request.Quantity != 1 {
		t.Errorf("Quantity = %v; want 1", got.Request.Quantity)
	}
}

// TestDecode_RTU_ReadHoldingRegistersResponse pins a Read
// Holding Registers response: byte_count=2, single register
// value 0x1234.
func TestDecode_RTU_ReadHoldingRegistersResponse(t *testing.T) {
	// Body: 01 03 02 12 34 → CRC over those 5 bytes
	// computed below; let's let test compute it.
	got, err := Decode("01 03 02 12 34 B5 33")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.CRCValid {
		t.Errorf("CRCValid = false; expected %s, got %s", got.CRCExpected, got.CRC)
	}
	if got.Response == nil {
		t.Fatal("Response nil for read response shape")
	}
	if got.Response.ByteCount == nil || *got.Response.ByteCount != 2 {
		t.Errorf("ByteCount = %v; want 2", got.Response.ByteCount)
	}
	if len(got.Response.RegisterValues) != 1 || got.Response.RegisterValues[0] != 0x1234 {
		t.Errorf("RegisterValues = %v; want [0x1234]", got.Response.RegisterValues)
	}
}

// TestDecode_RTU_WriteSingleCoil pins a Write Single Coil
// request/response: address 0x00AC, value 0xFF00 (ON).
func TestDecode_RTU_WriteSingleCoil(t *testing.T) {
	// Body: 01 05 00 AC FF 00 → CRC 4C 1B
	got, err := Decode("01 05 00 AC FF 00 4C 1B")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.CRCValid {
		t.Errorf("CRCValid = false; expected %s, got %s", got.CRCExpected, got.CRC)
	}
	if got.FunctionName != "Write Single Coil" {
		t.Errorf("FunctionName = %q", got.FunctionName)
	}
	if got.Request == nil {
		t.Fatal("Request nil")
	}
	if got.Request.OutputAddress == nil || *got.Request.OutputAddress != 0x00AC {
		t.Errorf("OutputAddress = %v; want 0x00AC", got.Request.OutputAddress)
	}
	if got.Request.OutputValue == nil || *got.Request.OutputValue != 0xFF00 {
		t.Errorf("OutputValue = %v; want 0xFF00 (ON)", got.Request.OutputValue)
	}
}

// TestDecode_RTU_ExceptionResponse pins an Illegal Data
// Address exception in response to a Read Holding Registers.
// Function code 0x83 (0x03 | 0x80), exception code 0x02.
func TestDecode_RTU_ExceptionResponse(t *testing.T) {
	// Body: 01 83 02 → CRC C0 F1
	got, err := Decode("01 83 02 C0 F1")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.CRCValid {
		t.Errorf("CRCValid = false; expected %s, got %s", got.CRCExpected, got.CRC)
	}
	if !got.IsException {
		t.Error("IsException = false; want true (FC 0x83)")
	}
	if got.ExceptionCode == nil || *got.ExceptionCode != 0x02 {
		t.Errorf("ExceptionCode = %v; want 0x02", got.ExceptionCode)
	}
	if got.ExceptionName != "Illegal Data Address" {
		t.Errorf("ExceptionName = %q", got.ExceptionName)
	}
	if !strings.Contains(got.FunctionName, "Read Holding Registers") {
		t.Errorf("FunctionName = %q; should reference original FC", got.FunctionName)
	}
}

// TestDecode_RTU_BadCRC surfaces CRCValid=false.
func TestDecode_RTU_BadCRC(t *testing.T) {
	got, err := Decode("01 03 00 00 00 01 AA BB")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.CRCValid {
		t.Error("CRCValid = true; want false for bogus CRC")
	}
	if got.CRC != "AABB" {
		t.Errorf("CRC = %q; want 'AABB' (wire-byte order)", got.CRC)
	}
}

// TestDecode_TCP_ReadHoldingRegistersRequest pins a Modbus
// TCP frame: TransactionID 0x0001, ProtocolID 0x0000,
// Length 0x0006, UnitID 0x01, FC 0x03, start 0x0000, qty
// 0x000A.
func TestDecode_TCP_ReadHoldingRegistersRequest(t *testing.T) {
	got, err := Decode("0001 0000 0006 01 03 0000 000A")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Format != "TCP" {
		t.Errorf("Format = %q; want TCP", got.Format)
	}
	if got.TransactionID == nil || *got.TransactionID != 1 {
		t.Errorf("TransactionID = %v; want 1", got.TransactionID)
	}
	if got.ProtocolID == nil || *got.ProtocolID != 0 {
		t.Errorf("ProtocolID = %v; want 0", got.ProtocolID)
	}
	if got.LengthField == nil || *got.LengthField != 6 {
		t.Errorf("LengthField = %v; want 6", got.LengthField)
	}
	if got.UnitID != 1 {
		t.Errorf("UnitID = %d", got.UnitID)
	}
	if got.FunctionCode != 0x03 {
		t.Errorf("FunctionCode = 0x%02X", got.FunctionCode)
	}
	if got.Request == nil {
		t.Fatal("Request nil")
	}
	if *got.Request.Quantity != 10 {
		t.Errorf("Quantity = %d; want 10", *got.Request.Quantity)
	}
}

// TestDecode_TCP_WriteMultipleRegisters covers the FC 0x10
// request shape: start + qty + byte_count + N×2-byte values.
func TestDecode_TCP_WriteMultipleRegisters(t *testing.T) {
	// 2 registers (0x000A, 0x0102) at start 0x0010
	// TCP header: txn=0001, proto=0000, len=0x000B,
	// unit=01, fc=10, start=0010, qty=0002, bc=04,
	// values=000A 0102
	got, err := Decode("0001 0000 000B 01 10 0010 0002 04 000A 0102")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Request == nil {
		t.Fatal("Request nil")
	}
	if *got.Request.StartAddress != 0x10 {
		t.Errorf("StartAddress = %d; want 0x10", *got.Request.StartAddress)
	}
	if *got.Request.Quantity != 2 {
		t.Errorf("Quantity = %d; want 2", *got.Request.Quantity)
	}
	if len(got.Request.RegisterValues) != 2 {
		t.Fatalf("RegisterValues count = %d; want 2", len(got.Request.RegisterValues))
	}
	if got.Request.RegisterValues[0] != 0x000A || got.Request.RegisterValues[1] != 0x0102 {
		t.Errorf("RegisterValues = %v; want [0x000A, 0x0102]", got.Request.RegisterValues)
	}
}

// TestDecode_TCP_ExceptionResponse pins a TCP exception
// response: Illegal Function (0x01) for FC 0x05.
func TestDecode_TCP_ExceptionResponse(t *testing.T) {
	// txn=0042, proto=0000, len=0003, unit=01, fc=85
	// (0x05|0x80), exception=01
	got, err := Decode("0042 0000 0003 01 85 01")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Format != "TCP" {
		t.Errorf("Format = %q", got.Format)
	}
	if !got.IsException {
		t.Error("IsException = false; want true")
	}
	if got.ExceptionName != "Illegal Function" {
		t.Errorf("ExceptionName = %q", got.ExceptionName)
	}
}

// TestDecode_RTU_WriteMultipleCoils pins FC 0x0F request:
// start 0x0013, qty 0x000A, bc=2, values 0xCD 0x01 (10 coils
// encoded LSB-first).
func TestDecode_RTU_WriteMultipleCoils(t *testing.T) {
	// Body: 01 0F 00 13 00 0A 02 CD 01 → CRC wire bytes 72 CB
	got, err := Decode("01 0F 00 13 00 0A 02 CD 01 72 CB")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.CRCValid {
		t.Errorf("CRCValid = false; expected %s, got %s", got.CRCExpected, got.CRC)
	}
	if got.Request == nil {
		t.Fatal("Request nil")
	}
	if *got.Request.Quantity != 10 {
		t.Errorf("Quantity = %d; want 10", *got.Request.Quantity)
	}
	if len(got.Request.CoilStatuses) != 10 {
		t.Fatalf("CoilStatuses count = %d; want 10", len(got.Request.CoilStatuses))
	}
	// 0xCD = 1100 1101 (LSB first) → bits 1,0,1,1,0,0,1,1
	// 0x01 = 0000 0001 → bits 1,0,0,0,0,0,0,0
	// First 10 coils: 1,0,1,1,0,0,1,1, 1,0
	wantCoils := []bool{true, false, true, true, false, false, true, true, true, false}
	for i, want := range wantCoils {
		if got.Request.CoilStatuses[i] != want {
			t.Errorf("CoilStatuses[%d] = %v; want %v", i, got.Request.CoilStatuses[i], want)
		}
	}
}

// TestDecode_TCPDetection — verify a 7-byte input that
// looks like RTU is NOT classified as TCP just because it's
// short.
func TestDecode_TCPDetection(t *testing.T) {
	// RTU frame: 01 03 00 00 00 01 84 0A
	got, err := Decode("01 03 00 00 00 01 84 0A")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Format != "RTU" {
		t.Errorf("Format = %q; want RTU (not TCP)", got.Format)
	}
}

// TestDecode_RejectsShort rejects frames shorter than the RTU
// minimum.
func TestDecode_RejectsShort(t *testing.T) {
	if _, err := Decode("01 03"); err == nil {
		t.Error("2-byte input: want error")
	}
}

// TestDecode_RejectsBadHex rejects garbage hex input.
func TestDecode_RejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
}

// TestCRC16 pins the polynomial against the classic Modbus
// reference vector from PI_MBUS_300 §6.2.4.
func TestCRC16(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint16
	}{
		// Wire bytes B8 39 → numeric value 0x39B8 (LE)
		{[]byte{0x01, 0x02, 0x00, 0xC4, 0x00, 0x16}, 0x39B8},
		{[]byte{0x01, 0x03, 0x00, 0x00, 0x00, 0x01}, 0x0A84},
		{[]byte{0x01, 0x06, 0x00, 0x01, 0x00, 0x03}, 0x0B98},
	}
	for _, c := range cases {
		if got := crc16(c.in); got != c.want {
			t.Errorf("crc16(% X) = 0x%04X; want 0x%04X", c.in, got, c.want)
		}
	}
}

// TestFunctionCodeNameTable spot-checks the table.
func TestFunctionCodeNameTable(t *testing.T) {
	cases := map[int]string{
		0x01: "Read Coils",
		0x03: "Read Holding Registers",
		0x05: "Write Single Coil",
		0x10: "Write Multiple Registers",
		0x2B: "Encapsulated Interface Transport (MEI)",
	}
	for fc, want := range cases {
		if got := functionCodeName(fc); got != want {
			t.Errorf("functionCodeName(0x%02X) = %q; want %q", fc, got, want)
		}
	}
}

// TestExceptionCodeNameTable spot-checks the table.
func TestExceptionCodeNameTable(t *testing.T) {
	cases := map[int]string{
		0x01: "Illegal Function",
		0x02: "Illegal Data Address",
		0x03: "Illegal Data Value",
		0x06: "Server Device Busy",
		0x0A: "Gateway Path Unavailable",
		0x0B: "Gateway Target Device Failed to Respond",
	}
	for ec, want := range cases {
		if got := exceptionCodeName(ec); got != want {
			t.Errorf("exceptionCodeName(0x%02X) = %q; want %q", ec, got, want)
		}
	}
}

// TestDecode_Separators tolerates :, -, _, whitespace.
func TestDecode_Separators(t *testing.T) {
	got, err := Decode("01:03_00 00-00 01 84 0A")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.CRCValid {
		t.Error("CRCValid = false")
	}
}
