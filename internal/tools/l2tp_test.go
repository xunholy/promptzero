package tools

import (
	"context"
	"strings"
	"testing"
)

// TestL2TPV3DecodeHandler_HELLO pins a canonical control
// HELLO with just the Message Type AVP.
func TestL2TPV3DecodeHandler_HELLO(t *testing.T) {
	in := "C803 0014 00000001 0000 0001 8008 0000 0000 0006"
	out, err := l2tpV3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Control Message"`,
		`"version": 3`,
		`"control_connection_id": 1`,
		`"message_type_name": "HELLO (Keepalive)"`,
		`"attribute_name": "Message Type"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestL2TPV3DecodeHandler_SCCRQ pins SCCRQ with Host Name and
// Vendor Name AVPs.
func TestL2TPV3DecodeHandler_SCCRQ(t *testing.T) {
	in := "C803 002C 00000001 0001 0000" +
		"8008 0000 0000 0001" +
		"800D 0000 0007 726F75746572 31" +
		"800B 0000 0008 4369 73 63 6F"
	out, err := l2tpV3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "SCCRQ (Start-Control-Connection-Request)"`,
		`"attribute_name": "Host Name"`,
		`"value_text": "router1"`,
		`"attribute_name": "Vendor Name"`,
		`"value_text": "Cisco"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestL2TPV3DecodeHandler_Data pins data message with session
// ID and payload preview.
func TestL2TPV3DecodeHandler_Data(t *testing.T) {
	in := "0003 00000064 DEADBEEF00112233"
	out, err := l2tpV3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Data Message"`,
		`"session_id": 100`,
		`"payload_hex": "DEADBEEF00112233"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestL2TPV3DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := l2tpV3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
