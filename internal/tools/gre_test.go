package tools

import (
	"context"
	"strings"
	"testing"
)

// TestGREDecodeHandler_BasicIPv4 pins a basic GRE packet
// (no optional fields, IPv4 inside) through the Spec handler.
func TestGREDecodeHandler_BasicIPv4(t *testing.T) {
	in := "00000800 AABBCCDD"
	out, err := greDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"variant": "standard GRE (RFC 2784/2890)"`,
		`"protocol_name": "IPv4"`,
		`"header_bytes": 4`,
		`"payload_length": 4`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestGREDecodeHandler_PPTPEnhanced pins PPTP Enhanced GRE
// with Call ID, Seq, and Ack.
func TestGREDecodeHandler_PPTPEnhanced(t *testing.T) {
	in := "3081 880B 12345678 000000A0 000000B0 AABBCCDD"
	out, err := greDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"variant": "PPTP Enhanced GRE (RFC 2637)"`,
		`"pptp_call_id": 22136`, // 0x5678
		`"ack_number": 176`,     // 0xB0
		`"protocol_name": "PPP (PPP-in-GRE)"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestGREDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := greDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestGREDecodeHandler_RejectsTruncatedHeader(t *testing.T) {
	_, err := greDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "0000"})
	if err == nil {
		t.Fatal("want error for truncated header")
	}
}
