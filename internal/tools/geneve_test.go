package tools

import (
	"context"
	"strings"
	"testing"
)

// TestGeneveDecodeHandler_BasicTEB pins a Geneve TEB packet
// (no options, inner Ethernet+IPv4) through the Spec handler.
func TestGeneveDecodeHandler_BasicTEB(t *testing.T) {
	in := "00006558 123456 00 AABBCCDDEEFF 112233445566 0800 DEADBEEF"
	out, err := geneveDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"protocol_name": "Transparent Ethernet Bridging"`,
		`"vni": 1193046`, // 0x123456
		`"dst_mac": "AA:BB:CC:DD:EE:FF"`,
		`"src_mac": "11:22:33:44:55:66"`,
		`"ether_type_name": "IPv4"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestGeneveDecodeHandler_WithOptions pins multiple Geneve
// options + critical-options-present flag.
func TestGeneveDecodeHandler_WithOptions(t *testing.T) {
	// OptLen=1 word, critical flag set, one option class 0x0101
	// (VMware) with C-bit on the option.
	in := "01406558 000001 00 01018000 AABBCCDDEEFF 112233445566 0800"
	out, err := geneveDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"critical_options_present": true`) {
		t.Errorf("expected critical_options_present true:\n%s", out)
	}
	if !strings.Contains(out, `"class_name": "VMware (NSX-T)"`) {
		t.Errorf("expected VMware class name:\n%s", out)
	}
}

func TestGeneveDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := geneveDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestGeneveDecodeHandler_RejectsTruncatedHeader(t *testing.T) {
	_, err := geneveDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "00006558"})
	if err == nil {
		t.Fatal("want error for truncated header")
	}
}
