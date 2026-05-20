package diameter

import (
	"strings"
	"testing"
)

func TestDecode_CER_OriginHostAndRealm(t *testing.T) {
	// Capabilities-Exchange-Request (cmd 257, R=1).
	// AVPs: Origin-Host="client.example.com",
	//       Origin-Realm="example.com".
	in := "01 000044 80 000101 00000000 12345678 87654321" +
		"00000108 40 00001A 636C69656E742E6578616D706C652E636F6D 0000" +
		"00000128 40 000013 6578616D706C652E636F6D 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandCode != 257 || r.CommandName != "Capabilities-Exchange-Request" {
		t.Errorf("command: %d %q", r.CommandCode, r.CommandName)
	}
	if !r.CommandFlagRequest || r.CommandFlagError {
		t.Errorf("flags: %+v", r)
	}
	if r.ApplicationID != 0 || r.ApplicationName != "Diameter Base" {
		t.Errorf("application: %d %q", r.ApplicationID, r.ApplicationName)
	}
	if r.HopByHopID != 0x12345678 || r.EndToEndID != 0x87654321 {
		t.Errorf("identifiers: hbh=%08X e2e=%08X",
			r.HopByHopID, r.EndToEndID)
	}
	if len(r.AVPs) != 2 {
		t.Fatalf("AVPs: %d", len(r.AVPs))
	}
	if r.AVPs[0].Code != 264 || r.AVPs[0].Name != "Origin-Host" ||
		r.AVPs[0].StringValue != "client.example.com" {
		t.Errorf("Origin-Host: %+v", r.AVPs[0])
	}
	if r.AVPs[1].Code != 296 || r.AVPs[1].Name != "Origin-Realm" ||
		r.AVPs[1].StringValue != "example.com" {
		t.Errorf("Origin-Realm: %+v", r.AVPs[1])
	}
}

func TestDecode_CEA_ResultCode_Success(t *testing.T) {
	// Capabilities-Exchange-Answer (cmd 257, R=0).
	// AVPs: Result-Code=2001, Origin-Host="server.example.com".
	in := "01 00003C 00 000101 00000000 12345678 87654321" +
		"0000010C 40 00000C 000007D1" +
		"00000108 40 00001A 7365727665722E6578616D706C652E636F6D 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "Capabilities-Exchange-Answer" {
		t.Errorf("command name: %q", r.CommandName)
	}
	if r.CommandFlagRequest {
		t.Errorf("R flag should be clear in answer")
	}
	if r.AVPs[0].Name != "Result-Code" ||
		r.AVPs[0].Uint32Value == nil || *r.AVPs[0].Uint32Value != 2001 {
		t.Errorf("Result-Code AVP: %+v", r.AVPs[0])
	}
	if r.AVPs[0].ResultClass != "Success (DIAMETER_SUCCESS)" {
		t.Errorf("result class: %q", r.AVPs[0].ResultClass)
	}
}

func TestDecode_S6a_UpdateLocationRequest(t *testing.T) {
	// 3GPP S6a Update-Location-Request (cmd 316 = 0x13C),
	// app ID 0x01000023 (16777251).
	in := "01 000028 80 00013C 01000023 12345678 87654321" +
		"00000107 40 000014 746573742D73657373696F6E"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.CommandName != "Update-Location-Request" {
		t.Errorf("command: %q", r.CommandName)
	}
	if !strings.Contains(r.ApplicationName, "S6a") {
		t.Errorf("application: %q", r.ApplicationName)
	}
	if r.AVPs[0].Name != "Session-Id" ||
		r.AVPs[0].StringValue != "test-session" {
		t.Errorf("Session-Id: %+v", r.AVPs[0])
	}
}

func TestDecode_VendorSpecificAVP(t *testing.T) {
	// AVP with V flag set: code 2, Vendor-ID 10415 (3GPP),
	// data 0xDEADBEEF (uint32).
	in := "01 000024 80 000101 00000000 12345678 87654321" +
		"00000002 C0 000010 000028AF DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.AVPs) != 1 {
		t.Fatalf("AVPs: %d", len(r.AVPs))
	}
	a := r.AVPs[0]
	if !a.FlagV || !a.FlagM {
		t.Errorf("flags V+M not set: %+v", a)
	}
	if a.VendorID == nil || *a.VendorID != 10415 {
		t.Errorf("vendor ID: %+v", a.VendorID)
	}
}

func TestDecode_HostIPAddressIPv4(t *testing.T) {
	// AVP Host-IP-Address (code 257) with IPv4 192.168.1.1.
	// AF=1 (IPv4) + 4-byte address. Body = 2 + 4 = 6 bytes,
	// total AVP = 8 + 6 = 14, padded to 16.
	in := "01 000024 80 000101 00000000 12345678 87654321" +
		"00000101 40 00000E 0001 C0A80101 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := r.AVPs[0]
	if a.Name != "Host-IP-Address" {
		t.Errorf("AVP name: %q", a.Name)
	}
	if a.AddressValue != "192.168.1.1" {
		t.Errorf("address: %q", a.AddressValue)
	}
}

func TestDecode_ErrorAnswer_5xxx(t *testing.T) {
	// CEA with E flag set + Result-Code 5012 (UNABLE_TO_COMPLY).
	// 5012 = 0x1394.
	in := "01 00001C 20 000101 00000000 12345678 87654321" +
		"0000010C 40 00000C 00001394"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.CommandFlagError {
		t.Errorf("E flag should be set")
	}
	if r.AVPs[0].ResultClass != "Permanent Failure" {
		t.Errorf("result class: %q", r.AVPs[0].ResultClass)
	}
}

func TestDecode_CommandNameTable(t *testing.T) {
	cases := map[int]string{
		257: "Capabilities-Exchange",
		258: "Re-Auth",
		271: "Accounting",
		272: "Credit-Control",
		274: "Abort-Session",
		275: "Session-Termination",
		280: "Device-Watchdog",
		282: "Disconnect-Peer",
		316: "Update-Location",
		317: "Cancel-Location",
		318: "Authentication-Information",
		319: "Insert-Subscriber-Data",
		320: "Delete-Subscriber-Data",
		321: "Purge-UE",
	}
	for k, v := range cases {
		if got := commandBaseName(k); got != v {
			t.Errorf("commandBaseName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_ApplicationNameTable(t *testing.T) {
	cases := map[uint32]string{
		0:          "Diameter Base",
		3:          "Accounting",
		4:          "Credit-Control (RFC 4006)",
		0x01000023: "3GPP S6a/S6d (TS 29.272)",
		0x01000016: "3GPP Gx (TS 29.212)",
		0xFFFFFFFF: "Diameter Relay",
	}
	for k, v := range cases {
		if got := applicationName(k); got != v {
			t.Errorf("applicationName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_ResultCodeClasses(t *testing.T) {
	cases := map[uint32]string{
		1001: "Informational",
		2001: "Success (DIAMETER_SUCCESS)",
		2002: "Success",
		3001: "Protocol Error",
		4001: "Transient Failure",
		5001: "Permanent Failure",
		5012: "Permanent Failure",
	}
	for k, v := range cases {
		if got := resultCodeClass(k); got != v {
			t.Errorf("resultCodeClass(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_AVPNameSpotCheck(t *testing.T) {
	cases := map[uint32]string{
		1:   "User-Name",
		257: "Host-IP-Address",
		263: "Session-Id",
		264: "Origin-Host",
		268: "Result-Code",
		283: "Destination-Realm",
		296: "Origin-Realm",
	}
	for k, v := range cases {
		if got := avpName(k); got != v {
			t.Errorf("avpName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_VersionMismatch_Note(t *testing.T) {
	// Version 2 (only 1 is defined).
	in := "02 000014 80 000101 00000000 12345678 87654321"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "version") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected version note in: %v", r.Notes)
	}
}

func TestDecode_LengthMismatch_Note(t *testing.T) {
	// Declared length 28 (0x1C) but only 20 bytes provided.
	in := "01 00001C 80 000101 00000000 12345678 87654321"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "declares") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected length-mismatch note in: %v", r.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "01 000014 80",
		"short":   "01 000014 80",
		"bad hex": "ZZ 000014 80 000101 00000000 12345678 87654321",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
