package tools

import (
	"context"
	"strings"
	"testing"
)

// TestDiameterDecodeHandler_CER pins a canonical Capabilities-
// Exchange-Request with Origin-Host + Origin-Realm.
func TestDiameterDecodeHandler_CER(t *testing.T) {
	in := "01 000044 80 000101 00000000 12345678 87654321" +
		"00000108 40 00001A 636C69656E742E6578616D706C652E636F6D 0000" +
		"00000128 40 000013 6578616D706C652E636F6D 00"
	out, err := diameterDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command_name": "Capabilities-Exchange-Request"`,
		`"application_name": "Diameter Base"`,
		`"command_flag_request": true`,
		`"name": "Origin-Host"`,
		`"string_value": "client.example.com"`,
		`"name": "Origin-Realm"`,
		`"string_value": "example.com"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestDiameterDecodeHandler_CEA_Success pins a Capabilities-
// Exchange-Answer with Result-Code 2001 (DIAMETER_SUCCESS).
func TestDiameterDecodeHandler_CEA_Success(t *testing.T) {
	in := "01 00003C 00 000101 00000000 12345678 87654321" +
		"0000010C 40 00000C 000007D1" +
		"00000108 40 00001A 7365727665722E6578616D706C652E636F6D 0000"
	out, err := diameterDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command_name": "Capabilities-Exchange-Answer"`,
		`"command_flag_request": false`,
		`"name": "Result-Code"`,
		`"uint32_value": 2001`,
		`"result_class": "Success (DIAMETER_SUCCESS)"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestDiameterDecodeHandler_S6aULR pins a 3GPP S6a Update-
// Location-Request.
func TestDiameterDecodeHandler_S6aULR(t *testing.T) {
	in := "01 000028 80 00013C 01000023 12345678 87654321" +
		"00000107 40 000014 746573742D73657373696F6E"
	out, err := diameterDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command_name": "Update-Location-Request"`,
		`"application_name": "3GPP S6a/S6d (TS 29.272)"`,
		`"name": "Session-Id"`,
		`"string_value": "test-session"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestDiameterDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := diameterDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
