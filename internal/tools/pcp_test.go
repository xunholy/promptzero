package tools

import (
	"context"
	"strings"
	"testing"
)

// TestPCPDecodeHandler_MapRequest pins a canonical MAP request.
func TestPCPDecodeHandler_MapRequest(t *testing.T) {
	in := "02 01 0000 00000E10" +
		"00000000000000000000FFFFC0A80164" +
		"DEADBEEFCAFEBABE12345678" +
		"06 000000" +
		"0050 1F90" +
		"00000000000000000000FFFF00000000"
	out, err := pcpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version": 2`,
		`"is_response": false`,
		`"opcode_name": "MAP"`,
		`"requested_lifetime_seconds": 3600`,
		`"pcp_client_ip_address": "192.168.1.100"`,
		`"protocol_name": "TCP"`,
		`"internal_port": 80`,
		`"suggested_external_port": 8080`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestPCPDecodeHandler_MapResponse pins a MAP response with
// granted external IP+port.
func TestPCPDecodeHandler_MapResponse(t *testing.T) {
	in := "02 81 00 00 00000E10 00003039 000000000000000000000000" +
		"DEADBEEFCAFEBABE12345678" +
		"06 000000" +
		"0050 3039" +
		"00000000000000000000FFFFCB007105"
	out, err := pcpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_response": true`,
		`"result_code_name": "SUCCESS"`,
		`"suggested_external_address": "203.0.113.5"`,
		`"suggested_external_port": 12345`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestPCPDecodeHandler_PeerRequest pins PEER opcode with
// remote peer tuple.
func TestPCPDecodeHandler_PeerRequest(t *testing.T) {
	in := "02 02 0000 00000E10" +
		"00000000000000000000FFFFC0A80164" +
		"DEADBEEFCAFEBABE12345678" +
		"06 000000" +
		"0050 1F90" +
		"00000000000000000000FFFF00000000" +
		"01BB 0000" +
		"00000000000000000000FFFF08080808"
	out, err := pcpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"opcode_name": "PEER"`,
		`"remote_peer_port": 443`,
		`"remote_peer_address": "8.8.8.8"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestPCPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := pcpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
