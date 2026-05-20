package tools

import (
	"context"
	"strings"
	"testing"
)

// TestNATPMPDecodeHandler_PublicAddressResponse pins the
// canonical 12-byte response with public IP.
func TestNATPMPDecodeHandler_PublicAddressResponse(t *testing.T) {
	in := "00 80 0000 00003039 CB007105"
	out, err := natpmpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version": 0`,
		`"opcode_name": "Public Address Response"`,
		`"is_response": true`,
		`"result_code_name": "SUCCESS"`,
		`"public_ip_address": "203.0.113.5"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestNATPMPDecodeHandler_MapUDPRequest pins a Map UDP
// request mapping internal 80 → external 8080.
func TestNATPMPDecodeHandler_MapUDPRequest(t *testing.T) {
	in := "00 01 0000 0050 1F90 00000E10"
	out, err := natpmpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"opcode_name": "Map UDP Request"`,
		`"protocol": "UDP"`,
		`"internal_port": 80`,
		`"suggested_external_port": 8080`,
		`"requested_lifetime_seconds": 3600`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestNATPMPDecodeHandler_MapTCPResponse pins a Map TCP
// response with granted external port.
func TestNATPMPDecodeHandler_MapTCPResponse(t *testing.T) {
	in := "00 82 0000 00003039 01BB 1F90 00000E10"
	out, err := natpmpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"opcode_name": "Map TCP Response"`,
		`"protocol": "TCP"`,
		`"mapped_external_port": 8080`,
		`"lifetime_seconds": 3600`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestNATPMPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := natpmpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
