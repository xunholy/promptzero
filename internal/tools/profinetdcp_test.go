package tools

import (
	"context"
	"strings"
	"testing"
)

// TestProfinetDCPDecodeHandler_IdentifyAll pins the multicast
// IdentifyAll request.
func TestProfinetDCPDecodeHandler_IdentifyAll(t *testing.T) {
	in := "FEFC 05 00 12345678 0001 0004 FF FF 0000"
	out, err := profinetDCPDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"frame_id_name": "DCP_Identify_Request"`,
		`"service_id_name": "Identify"`,
		`"service_type_name": "Request"`,
		`"option_name": "AllSelector"`,
		`"suboption_name": "All"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestProfinetDCPDecodeHandler_IdentifyResponse pins a response
// with vendor + station name + device ID.
func TestProfinetDCPDecodeHandler_IdentifyResponse(t *testing.T) {
	in := "FEFB 05 01 12345678 0000 0026 " +
		"02 01 00 09 00 01 53 49 45 4D 45 4E 53 00 " +
		"02 02 00 09 00 01 65 74 32 30 30 73 70 00 " +
		"02 03 00 06 00 01 00 2A 01 00"
	out, err := profinetDCPDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"vendor": "SIEMENS"`,
		`"name_of_station": "et200sp"`,
		`"vendor_id": 42`,
		`"device_id": 256`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestProfinetDCPDecodeHandler_IPParameter pins an IP set request.
func TestProfinetDCPDecodeHandler_IPParameter(t *testing.T) {
	in := "FEFD 04 00 ABCDEF01 0000 0012 " +
		"01 02 000E 0001 C0A8010A FFFFFF00 C0A80101"
	out, err := profinetDCPDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"service_id_name": "Set"`,
		`"ip_address": "192.168.1.10"`,
		`"subnet_mask": "255.255.255.0"`,
		`"gateway": "192.168.1.1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestProfinetDCPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := profinetDCPDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
