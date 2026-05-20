package tools

import (
	"context"
	"strings"
	"testing"
)

// TestDCCPDecodeHandler_Request pins a canonical DCCP-Request
// with Service Code.
func TestDCCPDecodeHandler_Request(t *testing.T) {
	in := "04D2 162E 04 00 ABCD 00 123456 CAFEBABE"
	out, err := dccpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"source_port": 1234`,
		`"destination_port": 5678`,
		`"type_name": "DCCP-Request"`,
		`"extended_sequence_numbers": false`,
		`"sequence_number": 1193046`,         // 0x123456 = 1193046
		`"request_service_code": 3405691582`, // 0xCAFEBABE
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestDCCPDecodeHandler_Reset pins a Reset with named Reset
// Code.
func TestDCCPDecodeHandler_Reset(t *testing.T) {
	in := "04D2 162E 07 00 ABCD 0F 00 010203040506" +
		"0000 0A0B0C0D0E0F" +
		"07 00 00 00"
	out, err := dccpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "DCCP-Reset"`,
		`"extended_sequence_numbers": true`,
		`"reset_code_name": "Connection Refused"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestDCCPDecodeHandler_Ack pins an Ack with extended seq.
func TestDCCPDecodeHandler_Ack(t *testing.T) {
	in := "04D2 162E 06 00 ABCD 07 00 010203040506" +
		"0000 0A0B0C0D0E0F"
	out, err := dccpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "DCCP-Ack"`,
		`"acknowledgement_number": 11042563100175`, // 0x0A0B0C0D0E0F
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestDCCPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := dccpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
