package s7comm

import (
	"strings"
	"testing"
)

// TestDecodeReadVarJob pins a canonical Read_Var job request.
func TestDecodeReadVarJob(t *testing.T) {
	// TPKT: 03 00 + length (uint16 BE).
	// Frame total = 4 TPKT + 3 COTP (LI=2, type=F0, tpdu=0) +
	// 10 S7 + 14 params + 0 data = 31 bytes.
	// COTP: LI=02, type=F0, tpdu=80 (EOT bit set + tpdu 0).
	// S7: 32 01 0000 0001 000E 0000 — protoID=32, ROSCTR=01
	// Job_Request, reserved 0000, PDU ref 0x0001, param len
	// 0x000E (14), data len 0.
	// Params: 04 (Read_Var) + 01 (ItemCount=1) + 12 ItemSpec
	// bytes (synthetic): 12 0A 10 02 00 01 00 01 84 00 00 00.
	in := "03 00 00 1F " +
		"02 F0 80 " +
		"32 01 0000 0001 000E 0000 " +
		"04 01 12 0A 10 02 00 01 00 01 84 00 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TPKTVersion != 3 || r.TPKTLength != 31 {
		t.Errorf("tpkt: ver=%d len=%d want 3/31", r.TPKTVersion, r.TPKTLength)
	}
	if r.COTPPDUType != 0xF0 || r.COTPPDUTypeName != "DT (Data)" {
		t.Errorf("cotp type: got %s (0x%X)", r.COTPPDUTypeName, r.COTPPDUType)
	}
	if !r.COTPEndOfTSDU {
		t.Errorf("EOT bit should be set")
	}
	if r.S7ProtocolID != 0x32 {
		t.Errorf("s7 protoID: got 0x%X want 0x32", r.S7ProtocolID)
	}
	if r.ROSCTRName != "Job_Request" {
		t.Errorf("rosctr: got %q want Job_Request", r.ROSCTRName)
	}
	if r.PDUReference != 1 {
		t.Errorf("pdu ref: got %d want 1", r.PDUReference)
	}
	if r.ParameterLength != 14 || r.DataLength != 0 {
		t.Errorf("lengths: param=%d data=%d want 14/0", r.ParameterLength, r.DataLength)
	}
	if r.FunctionName != "Read_Var" {
		t.Errorf("function: got %q want Read_Var", r.FunctionName)
	}
}

// TestDecodeAckDataResponse pins an Ack_Data response with the
// error-class/error-code field present and a Read_Var function.
func TestDecodeAckDataResponse(t *testing.T) {
	// COTP: LI=02, type=F0, tpdu=80. S7: 32 03 0000 0001 0002
	// 0006 00 00 — ROSCTR=03 Ack_Data, errorClass=0 errorCode=0,
	// paramLen=2 (function + ItemCount), dataLen=6 (one data
	// item).
	// Params: 04 01 (Read_Var + 1 item).
	// Data: 0xFF 04 0010 ABCD (Return code OK + transport size
	// + length 16 bits + payload ABCD).
	in := "03 00 00 1B " +
		"02 F0 80 " +
		"32 03 0000 0001 0002 0006 00 00 " +
		"04 01 " +
		"FF 04 0010 ABCD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ROSCTRName != "Ack_Data" {
		t.Errorf("rosctr: got %q want Ack_Data", r.ROSCTRName)
	}
	if r.ErrorClassName != "No_Error" {
		t.Errorf("errorClass: got %q want No_Error", r.ErrorClassName)
	}
	if r.FunctionName != "Read_Var" {
		t.Errorf("function: got %q want Read_Var", r.FunctionName)
	}
	if r.DataHex != "FF040010ABCD" {
		t.Errorf("data hex: got %q want FF040010ABCD", r.DataHex)
	}
}

// TestDecodePLCControl pins a PLC_Control (start/stop CPU)
// function code from a Job_Request.
func TestDecodePLCControl(t *testing.T) {
	// paramLen=4 (function + 3 bytes of opaque parameters);
	// dataLen=0.
	in := "03 00 00 15 " +
		"02 F0 80 " +
		"32 01 0000 0010 0004 0000 " +
		"28 00 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.FunctionName != "PLC_Control" {
		t.Errorf("function: got %q want PLC_Control", r.FunctionName)
	}
	if r.PDUReference != 0x10 {
		t.Errorf("pdu ref: got %d want 16", r.PDUReference)
	}
}

// TestDecodeSetupCommunication pins the Setup_Communication
// PDU-Length negotiation (handshake after CR/CC).
func TestDecodeSetupCommunication(t *testing.T) {
	// paramLen=8 (function 0xF0 + Reserved + Max Amq Caller +
	// Max Amq Callee + PDU length = 0x01E0/480 bytes).
	in := "03 00 00 19 " +
		"02 F0 80 " +
		"32 01 0000 0001 0008 0000 " +
		"F0 00 00 01 00 01 01 E0"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.FunctionName != "Setup_Communication" {
		t.Errorf("function: got %q want Setup_Communication", r.FunctionName)
	}
}

// TestDecodeCOTPConnectionRequest pins a CR PDU (no S7 header
// follows; CR is COTP-only).
func TestDecodeCOTPConnectionRequest(t *testing.T) {
	// TPKT length 22; COTP LI=11, type=E0, then 14 bytes of
	// CR parameters (DSTREF + SRCREF + Class + Calling/Called
	// TSAP).
	in := "03 00 00 16 " +
		"11 E0 00 00 00 01 00 C0 01 0A C1 02 01 00 C2 02 01 02"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.COTPPDUTypeName != "CR (Connection Request)" {
		t.Errorf("cotp type: got %q", r.COTPPDUTypeName)
	}
	if r.S7ProtocolID != 0 {
		t.Errorf("s7 fields should be zero for COTP-only CR PDU")
	}
}

// TestROSCTRNameTable spot-checks every catalogued ROSCTR.
func TestROSCTRNameTable(t *testing.T) {
	cases := map[int]string{
		0x01: "Job_Request", 0x02: "Ack",
		0x03: "Ack_Data", 0x07: "Userdata",
	}
	for k, v := range cases {
		if got := rosctrName(k); got != v {
			t.Errorf("rosctrName(0x%02X) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(rosctrName(0xFE), "uncatalogued") {
		t.Errorf("rosctrName(0xFE) should mark uncatalogued")
	}
}

// TestFunctionNameTable spot-checks the function codes.
func TestFunctionNameTable(t *testing.T) {
	cases := map[int]string{
		0x00: "CPU_services", 0x04: "Read_Var",
		0x05: "Write_Var", 0x28: "PLC_Control",
		0xF0: "Setup_Communication", 0x1D: "Start_Upload",
	}
	for k, v := range cases {
		if got := functionName(k); got != v {
			t.Errorf("functionName(0x%02X) = %q want %q", k, got, v)
		}
	}
}

// TestErrorClassNameTable spot-checks the documented classes.
func TestErrorClassNameTable(t *testing.T) {
	cases := map[int]string{
		0x00: "No_Error", 0x81: "Application_Relationship",
		0x83: "No_Resources_Available", 0x87: "Access_Error",
	}
	for k, v := range cases {
		if got := errorClassName(k); got != v {
			t.Errorf("errorClassName(0x%02X) = %q want %q", k, got, v)
		}
	}
}

// TestCOTPPDUTypeNameTable spot-checks PDU type names.
func TestCOTPPDUTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0xE0: "CR (Connection Request)",
		0xD0: "CC (Connection Confirm)",
		0xF0: "DT (Data)",
		0x80: "DR (Disconnect Request)",
	}
	for k, v := range cases {
		if got := cotpPDUTypeName(k); got != v {
			t.Errorf("cotpPDUTypeName(0x%02X) = %q want %q", k, got, v)
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

func TestDecodeRejectsShortTPKT(t *testing.T) {
	if _, err := Decode("03 00 00"); err == nil {
		t.Fatal("want error for short TPKT")
	}
}

func TestDecodeRejectsBadTPKTVersion(t *testing.T) {
	if _, err := Decode("04 00 00 07 02 F0 80"); err == nil {
		t.Fatal("want error when TPKT version != 0x03")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 6)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
