package tools

import (
	"context"
	"strings"
	"testing"
)

// TestCDPDecodeHandler_BasicSwitch pins a Cisco switch
// advertisement with Device ID + Capabilities + Software
// Version through the Spec handler.
func TestCDPDecodeHandler_BasicSwitch(t *testing.T) {
	in := "02 B4 0000" +
		"0001 000B 53776974636831" +
		"0004 0008 00000008" +
		"0005 0012 43697363 6F20494F 5320 31322E32"
	out, err := cdpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version": 2`,
		`"ttl_seconds": 180`,
		`"device_id": "Switch1"`,
		`"flags_decoded": "Switch (Layer 2)"`,
		`"software_version": "Cisco IOS 12.2"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestCDPDecodeHandler_Addresses pins an Addresses TLV with
// one IPv4 entry.
func TestCDPDecodeHandler_Addresses(t *testing.T) {
	in := "02 B4 0000" +
		"0001 0008 51323232" + // Device ID "Q222" (4 bytes body)
		"0002 0011 00000001 01 01 CC 0004 C0A80101"
	out, err := cdpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"protocol_name": "IPv4 (NLPID 0xCC)"`) {
		t.Errorf("expected IPv4 NLPID:\n%s", out)
	}
	if !strings.Contains(out, `"address": "192.168.1.1"`) {
		t.Errorf("expected 192.168.1.1:\n%s", out)
	}
}

func TestCDPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := cdpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestCDPDecodeHandler_RejectsTruncatedTLV(t *testing.T) {
	_, err := cdpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "02B40000 0001 000B 5377"})
	if err == nil {
		t.Fatal("want error for truncated TLV")
	}
}
