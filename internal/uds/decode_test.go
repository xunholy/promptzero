// SPDX-License-Identifier: AGPL-3.0-or-later

package uds

import "testing"

func TestDecode_NegativeResponse(t *testing.T) {
	// 7F 27 35 = SecurityAccess -> invalidKey
	u, err := Decode("7F 27 35")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Direction != "negative_response" {
		t.Errorf("direction = %s, want negative_response", u.Direction)
	}
	if u.Service != "SecurityAccess" {
		t.Errorf("service = %s, want SecurityAccess", u.Service)
	}
	if u.NRC == nil || *u.NRC != 0x35 || u.NRCName != "invalidKey" {
		t.Errorf("nrc = %v %q, want 0x35 invalidKey", u.NRC, u.NRCName)
	}
}

func TestDecode_NegativeResponsePending(t *testing.T) {
	u, err := Decode("7F3178") // RoutineControl, responsePending
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Service != "RoutineControl" || u.NRCName != "requestCorrectlyReceived-ResponsePending" {
		t.Errorf("got %s / %s", u.Service, u.NRCName)
	}
}

func TestDecode_RequestSession(t *testing.T) {
	// 10 03 = DiagnosticSessionControl -> extendedDiagnosticSession
	u, err := Decode("1003")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Direction != "request" || u.Service != "DiagnosticSessionControl" {
		t.Errorf("got %s / %s", u.Direction, u.Service)
	}
	if u.SubFunction == nil || *u.SubFunction != 0x03 || u.SubFunctionName != "extendedDiagnosticSession" {
		t.Errorf("subfn = %v %q", u.SubFunction, u.SubFunctionName)
	}
}

func TestDecode_PositiveResponse(t *testing.T) {
	// 50 03 ... = positive response to DiagnosticSessionControl (0x10+0x40)
	u, err := Decode("5003001932")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Direction != "positive_response" || u.Service != "DiagnosticSessionControl" {
		t.Errorf("got %s / %s", u.Direction, u.Service)
	}
}

func TestDecode_SuppressPositiveResponse(t *testing.T) {
	// 3E 80 = TesterPresent with suppressPositiveResponse bit set
	u, err := Decode("3E80")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Service != "TesterPresent" {
		t.Errorf("service = %s", u.Service)
	}
	if !u.SuppressPositiveResponse {
		t.Error("expected suppress_positive_response = true")
	}
	if u.SubFunction == nil || *u.SubFunction != 0x00 || u.SubFunctionName != "zeroSubFunction" {
		t.Errorf("subfn = %v %q", u.SubFunction, u.SubFunctionName)
	}
}

func TestDecode_ReadDataByIdentifierVIN(t *testing.T) {
	// 22 F1 90 = ReadDataByIdentifier, DID 0xF190 (VIN)
	u, err := Decode("22F190")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Service != "ReadDataByIdentifier" {
		t.Errorf("service = %s", u.Service)
	}
	if u.DataIdentifier == nil || *u.DataIdentifier != 0xF190 || u.DataIdentifierName != "VIN" {
		t.Errorf("DID = %v %q, want 0xF190 VIN", u.DataIdentifier, u.DataIdentifierName)
	}
}

func TestDecode_SecurityAccessRequestSeed(t *testing.T) {
	// 27 01 = SecurityAccess requestSeed level 1 (sub-function, no enum name)
	u, err := Decode("2701")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Service != "SecurityAccess" || u.SubFunction == nil || *u.SubFunction != 0x01 {
		t.Errorf("got %s subfn %v", u.Service, u.SubFunction)
	}
}

func TestDecode_UnknownService(t *testing.T) {
	// 0xBA is not a known request SID and 0xBA-0x40=0x7A is not either.
	u, err := Decode("BA01")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Direction != "request" {
		t.Errorf("direction = %s", u.Direction)
	}
	if len(u.Notes) == 0 {
		t.Error("expected a note for an unknown service")
	}
}

func TestDecode_Errors(t *testing.T) {
	for _, in := range []string{"", "zz"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q): expected error", in)
		}
	}
}
