package tools

import (
	"context"
	"strings"
	"testing"
)

// TestARPDecodeHandler_IPv4Request pins a canonical IPv4 ARP
// Request through the Spec handler.
func TestARPDecodeHandler_IPv4Request(t *testing.T) {
	in := "0001 0800 06 04 0001 001122334455 C0A80101 000000000000 C0A80102"
	out, err := arpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"hardware_type_name": "Ethernet"`,
		`"protocol_type_name": "IPv4"`,
		`"operation_name": "Request"`,
		`"sender_hardware_address": "00:11:22:33:44:55"`,
		`"sender_protocol_address": "192.168.1.1"`,
		`"target_protocol_address": "192.168.1.2"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestARPDecodeHandler_GratuitousARP pins the gratuitous-ARP
// detection note.
func TestARPDecodeHandler_GratuitousARP(t *testing.T) {
	in := "0001 0800 06 04 0002 001122334455 C0A80101 FFFFFFFFFFFF C0A80101"
	out, err := arpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "Gratuitous") {
		t.Errorf("expected Gratuitous note:\n%s", out)
	}
}

func TestARPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := arpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestARPDecodeHandler_RejectsTruncatedHeader(t *testing.T) {
	_, err := arpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "00010800"})
	if err == nil {
		t.Fatal("want error for truncated header")
	}
}
