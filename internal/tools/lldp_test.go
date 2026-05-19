package tools

import (
	"context"
	"strings"
	"testing"
)

// TestLLDPDecodeHandler_MinimalLLDPDU pins a canonical 3-TLV
// LLDPDU through the Spec handler.
func TestLLDPDecodeHandler_MinimalLLDPDU(t *testing.T) {
	in := "0207 04 001122334455" +
		"0405 05 65746830" +
		"0602 0078" +
		"0000"
	out, err := lldpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Chassis ID"`,
		`"mac": "00:11:22:33:44:55"`,
		`"type_name": "Port ID"`,
		`"id_text": "eth0"`,
		`"ttl_seconds": 120`,
		`"type_name": "End of LLDPDU"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestLLDPDecodeHandler_ManagementAddress pins a Management
// Address TLV with IPv4 + ifIndex.
func TestLLDPDecodeHandler_ManagementAddress(t *testing.T) {
	in := "0207 04 001122334455" +
		"0405 05 65746830" +
		"0602 0078" +
		"100C 05 01 C0A80101 02 00000001 00" +
		"0000"
	out, err := lldpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"address_subtype_name": "IPv4"`) {
		t.Errorf("expected IPv4 subtype:\n%s", out)
	}
	if !strings.Contains(out, `"address": "192.168.1.1"`) {
		t.Errorf("expected 192.168.1.1:\n%s", out)
	}
	if !strings.Contains(out, `"interface_subtype_name": "ifIndex"`) {
		t.Errorf("expected ifIndex:\n%s", out)
	}
}

func TestLLDPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := lldpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestLLDPDecodeHandler_RejectsTruncatedTLV(t *testing.T) {
	_, err := lldpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "0207 04 0011"})
	if err == nil {
		t.Fatal("want error for truncated TLV")
	}
}
