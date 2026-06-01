// SPDX-License-Identifier: AGPL-3.0-or-later

package kwp

import "testing"

func TestDecode_NegativeResponse(t *testing.T) {
	// 7F 21 31 = ReadDataByLocalIdentifier -> requestOutOfRange
	u, err := Decode("7F 21 31")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Direction != "negative_response" {
		t.Errorf("direction = %s", u.Direction)
	}
	if u.Service != "ReadDataByLocalIdentifier" {
		t.Errorf("service = %s, want ReadDataByLocalIdentifier", u.Service)
	}
	if u.NRC == nil || *u.NRC != 0x31 || u.NRCName != "requestOutOfRange" {
		t.Errorf("nrc = %v %q", u.NRC, u.NRCName)
	}
}

func TestDecode_NegativeResponsePending(t *testing.T) {
	u, err := Decode("7F1078")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Service != "StartDiagnosticSession" || u.NRCName != "requestCorrectlyReceived-ResponsePending" {
		t.Errorf("got %s / %s", u.Service, u.NRCName)
	}
}

// TestDecode_LocalIdentifierService confirms the KWP-distinct 0x21 service
// (which UDS does not define) decodes correctly with its local identifier.
func TestDecode_LocalIdentifierService(t *testing.T) {
	u, err := Decode("2101")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Direction != "request" || u.Service != "ReadDataByLocalIdentifier" {
		t.Errorf("got %s / %s", u.Direction, u.Service)
	}
	if u.ParamByte == nil || *u.ParamByte != 0x01 || u.ParamLabel != "local_identifier" {
		t.Errorf("param = %v %q", u.ParamByte, u.ParamLabel)
	}
}

func TestDecode_StartCommunication(t *testing.T) {
	// 0x81 StartCommunication is a KWP-specific service absent from UDS.
	u, err := Decode("81")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Service != "StartCommunication" || u.Direction != "request" {
		t.Errorf("got %s / %s", u.Service, u.Direction)
	}
}

func TestDecode_PositiveResponse(t *testing.T) {
	// 0x61 = positive response to 0x21 (0x21+0x40).
	u, err := Decode("6101AABB")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Direction != "positive_response" || u.Service != "ReadDataByLocalIdentifier" {
		t.Errorf("got %s / %s", u.Direction, u.Service)
	}
	if u.PayloadHex != "AABB" {
		t.Errorf("payload = %s, want AABB", u.PayloadHex)
	}
}

// TestDecode_DistinctFromUDS documents that KWP 0x3B (WriteDataByLocal-
// Identifier) is a real KWP service, where UDS leaves 0x3B unassigned.
func TestDecode_DistinctFromUDS(t *testing.T) {
	u, err := Decode("3B0512")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Service != "WriteDataByLocalIdentifier" {
		t.Errorf("0x3B service = %s, want WriteDataByLocalIdentifier", u.Service)
	}
	if u.ParamLabel != "local_identifier" || u.ParamByte == nil || *u.ParamByte != 0x05 {
		t.Errorf("param = %v %q", u.ParamByte, u.ParamLabel)
	}
}

func TestDecode_UnknownService(t *testing.T) {
	u, err := Decode("BB01")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(u.Notes) == 0 {
		t.Error("expected a note for unknown service")
	}
}

func TestDecode_Errors(t *testing.T) {
	for _, in := range []string{"", "zz"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q): expected error", in)
		}
	}
}

func FuzzDecodeBytes(f *testing.F) {
	for _, s := range [][]byte{{}, {0x7F}, {0x7F, 0x21}, {0x21}, {0x81}, {0x61, 0x01}, {0xBB}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeBytes(b) })
}
