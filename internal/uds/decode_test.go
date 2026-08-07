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

// TestDecode_DynamicallyDefineDataIdentifier pins the 0x2C fix. Per ISO
// 14229-1 the layout is SID | definitionType(sub-function) | DDDI(2) |
// … — so the sub-function must be read before the identifier. Before the
// fix 0x2C was absent from hasSubFunction, so the sub-function was
// dropped and the DDDI read one byte early (0x01F2 instead of 0xF201).
func TestDecode_DynamicallyDefineDataIdentifier(t *testing.T) {
	// 2C 01 F201 F190 0101 — defineByIdentifier, DDDI 0xF201, source spec.
	u, err := Decode("2C01F201F1900101")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if u.Service != "DynamicallyDefineDataIdentifier" {
		t.Errorf("service = %s", u.Service)
	}
	if u.SubFunction == nil || *u.SubFunction != 0x01 {
		t.Fatalf("SubFunction = %v; want 0x01", u.SubFunction)
	}
	if u.SubFunctionName != "defineByIdentifier" {
		t.Errorf("SubFunctionName = %q; want defineByIdentifier", u.SubFunctionName)
	}
	if u.DataIdentifier == nil || *u.DataIdentifier != 0xF201 {
		t.Errorf("DataIdentifier = %v; want 0xF201 (read after the sub-function)", u.DataIdentifier)
	}
	if u.PayloadHex != "F1900101" {
		t.Errorf("PayloadHex = %q; want F1900101", u.PayloadHex)
	}
}

// TestDecode_DIDServicesStructureIdentifier covers the sibling sweep:
// 0x24 (ReadScalingDataByIdentifier) and 0x2F
// (InputOutputControlByIdentifier) are DID-first services (like
// 0x22/0x2E) whose 2-byte identifier was previously left in the raw
// payload instead of being surfaced as DataIdentifier.
func TestDecode_DIDServicesStructureIdentifier(t *testing.T) {
	cases := []struct {
		hexIn   string
		service string
		did     int
		payload string
	}{
		{"24F19012", "ReadScalingDataByIdentifier", 0xF190, "12"},
		{"2FF19003FF", "InputOutputControlByIdentifier", 0xF190, "03FF"},
	}
	for _, c := range cases {
		u, err := Decode(c.hexIn)
		if err != nil {
			t.Fatalf("Decode(%s): %v", c.hexIn, err)
		}
		if u.Service != c.service {
			t.Errorf("%s: service = %s; want %s", c.hexIn, u.Service, c.service)
		}
		if u.SubFunction != nil {
			t.Errorf("%s: unexpected SubFunction %v (service has no sub-function)", c.hexIn, *u.SubFunction)
		}
		if u.DataIdentifier == nil || *u.DataIdentifier != c.did {
			t.Errorf("%s: DataIdentifier = %v; want 0x%04X", c.hexIn, u.DataIdentifier, c.did)
		}
		if u.PayloadHex != c.payload {
			t.Errorf("%s: PayloadHex = %q; want %q", c.hexIn, u.PayloadHex, c.payload)
		}
	}
}
