package tools

import (
	"context"
	"strings"
	"testing"
)

// TestGTPUDecodeHandler_BasicGPDU pins a canonical G-PDU
// (no optional fields, inner IPv4) through the Spec handler.
func TestGTPUDecodeHandler_BasicGPDU(t *testing.T) {
	in := "30FF 0014 11223344" +
		"45000014 12340000 40110000 7F000001 7F000001"
	out, err := gtpUDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "G-PDU (user-plane data)"`,
		`"teid_hex": "0x11223344"`,
		`"payload_guess": "IPv4 (first nibble 0x4)"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestGTPUDecodeHandler_5G_PDUSessionContainer pins a 5G N3
// G-PDU with a PDU Session Container extension header.
func TestGTPUDecodeHandler_5G_PDUSessionContainer(t *testing.T) {
	in := "34FF 001C 11223344 0000 00 85" +
		"01 0001 00" +
		"45000014 12340000 40110000 7F000001 7F000001"
	out, err := gtpUDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "PDU Session Container") {
		t.Errorf("expected PDU Session Container name:\n%s", out)
	}
	if !strings.Contains(out, `"extension_header_flag": true`) {
		t.Errorf("expected E flag true:\n%s", out)
	}
}

func TestGTPUDecodeHandler_EchoRequest(t *testing.T) {
	out, err := gtpUDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "3001000000000000"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"message_type_name": "Echo Request"`) {
		t.Errorf("expected Echo Request:\n%s", out)
	}
}

func TestGTPUDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := gtpUDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
