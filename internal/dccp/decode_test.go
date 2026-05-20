package dccp

import (
	"strings"
	"testing"
)

func TestDecode_Request_ShortHeader(t *testing.T) {
	// DCCP-Request (Type=0), X=0 (short seq), Source=1234,
	// Dest=5678, Data Offset=4 (16 bytes header+body),
	// CCVal=0, CsCov=0, Seq=0x123456, Service Code=0xCAFEBABE.
	// Short header: bytes 0-7 generic top + byte 8 type byte
	// + bytes 9-11 24-bit seq = 12 bytes. Then 4-byte service
	// code = 16 bytes total.
	in := "04D2 162E 04 00 ABCD 00 123456 CAFEBABE"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.SourcePort != 1234 || r.DestinationPort != 5678 {
		t.Errorf("ports: %d → %d", r.SourcePort, r.DestinationPort)
	}
	if r.TypeName != "DCCP-Request" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.Extended {
		t.Errorf("X bit should be clear")
	}
	if r.SequenceNumber != 0x123456 {
		t.Errorf("seq: %X", r.SequenceNumber)
	}
	if r.RequestServiceCode == nil || *r.RequestServiceCode != 0xCAFEBABE {
		t.Errorf("service code: %+v", r.RequestServiceCode)
	}
}

func TestDecode_Response_ExtendedHeader(t *testing.T) {
	// DCCP-Response (Type=1), X=1 (extended seq).
	// Type byte: Type=1 X=1 → 0b00000011 = 0x03.
	// Extended header: bytes 0-7 + byte 8 type + byte 9
	// reserved + bytes 10-15 48-bit seq = 16 bytes.
	// Then 8-byte Ack subheader + 4-byte Service Code = 28
	// bytes total. Data Offset = 7 words (28/4).
	// Seq = 0x010203040506, Ack = 0x0A0B0C0D0E0F.
	in := "04D2 162E 07 00 ABCD 03 00 010203040506" +
		"0000 0A0B0C0D0E0F" + // Ack subheader (8 bytes)
		"CAFEBABE" // Service Code (4 bytes)
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "DCCP-Response" {
		t.Errorf("type: %q", r.TypeName)
	}
	if !r.Extended {
		t.Errorf("X bit should be set")
	}
	if r.SequenceNumber != 0x010203040506 {
		t.Errorf("seq: %X", r.SequenceNumber)
	}
	if r.AckNumber == nil || *r.AckNumber != 0x0A0B0C0D0E0F {
		t.Errorf("ack: %+v", r.AckNumber)
	}
	if r.ResponseServiceCode == nil || *r.ResponseServiceCode != 0xCAFEBABE {
		t.Errorf("service code: %+v", r.ResponseServiceCode)
	}
}

func TestDecode_Ack_ExtendedHeader(t *testing.T) {
	// DCCP-Ack (Type=3), X=1. Data Offset = 6 words (24 bytes).
	// Type byte: Type=3 X=1 → 0b00000111 = 0x07.
	in := "04D2 162E 06 00 ABCD 07 00 010203040506" +
		"0000 0A0B0C0D0E0F"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "DCCP-Ack" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.AckNumber == nil || *r.AckNumber != 0x0A0B0C0D0E0F {
		t.Errorf("ack: %+v", r.AckNumber)
	}
}

func TestDecode_Reset_WithCode(t *testing.T) {
	// DCCP-Reset (Type=7), X=1. Data Offset = 7 words (28 bytes).
	// Type byte: Type=7 X=1 → 0b00001111 = 0x0F.
	// Reset Code = 7 (Connection Refused).
	in := "04D2 162E 07 00 ABCD 0F 00 010203040506" +
		"0000 0A0B0C0D0E0F" + // Ack subheader (8 bytes)
		"07 00 00 00" // Reset code + Data1/2/3 (4 bytes)
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "DCCP-Reset" {
		t.Errorf("type: %q", r.TypeName)
	}
	rb := r.ResetBody
	if rb == nil {
		t.Fatal("Reset body nil")
	}
	if rb.ResetCode != 7 || rb.ResetCodeName != "Connection Refused" {
		t.Errorf("reset code: %d %q", rb.ResetCode, rb.ResetCodeName)
	}
	if rb.AckNumber != 0x0A0B0C0D0E0F {
		t.Errorf("reset ack: %X", rb.AckNumber)
	}
}

func TestDecode_Data_ShortHeader(t *testing.T) {
	// DCCP-Data (Type=2), X=0.
	// Type byte: Type=2 X=0 → 0b00000100 = 0x04.
	in := "04D2 162E 03 00 ABCD 04 00 123456"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "DCCP-Data" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.Extended {
		t.Errorf("X bit should be clear")
	}
	// Data has no per-type body fields beyond the generic header.
	if r.RequestServiceCode != nil {
		t.Errorf("Data should not populate service code")
	}
}

func TestDecode_TypeNameTable(t *testing.T) {
	cases := map[int]string{
		0: "DCCP-Request",
		1: "DCCP-Response",
		2: "DCCP-Data",
		3: "DCCP-Ack",
		4: "DCCP-DataAck",
		5: "DCCP-CloseReq",
		6: "DCCP-Close",
		7: "DCCP-Reset",
		8: "DCCP-Sync",
		9: "DCCP-SyncAck",
	}
	for k, v := range cases {
		if got := typeName(k); got != v {
			t.Errorf("typeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_ResetCodeTable(t *testing.T) {
	cases := map[int]string{
		0:  "Unspecified",
		1:  "Closed",
		2:  "Aborted",
		3:  "No Connection",
		4:  "Packet Error",
		5:  "Option Error",
		6:  "Mandatory Error",
		7:  "Connection Refused",
		8:  "Bad Service Code",
		9:  "Too Busy",
		10: "Bad Init Cookie",
		11: "Aggression Penalty",
	}
	for k, v := range cases {
		if got := resetCodeName(k); got != v {
			t.Errorf("resetCodeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_CCValAndCsCov(t *testing.T) {
	// CCVal=0xA, CsCov=0x5 packed into byte 5: 0xA5.
	in := "04D2 162E 03 A5 ABCD 04 00 123456"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CCVal != 0xA {
		t.Errorf("CCVal: %d", r.CCVal)
	}
	if r.CsCov != 0x5 {
		t.Errorf("CsCov: %d", r.CsCov)
	}
}

func TestDecode_UncataloguedType(t *testing.T) {
	// Type=15 (reserved per RFC 4340).
	// Type byte: Type=15 X=0 → 0b00011110 = 0x1E.
	in := "04D2 162E 03 00 ABCD 1E 00 123456"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.TypeName, "uncatalogued") {
		t.Errorf("expected uncatalogued type, got %q", r.TypeName)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"odd hex":        "04D2 162E 03 00 ABCD 00 00 12345",
		"short":          "04D2 162E",
		"bad hex":        "ZZD2 162E 03 00 ABCD 00 00 123456",
		"extended trunc": "04D2 162E 06 00 ABCD 03 00 010203",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
